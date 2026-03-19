/*
 * client_integration.cs — TamozaKeyGen License Validator (C# / .NET Client)
 *
 * Drop this file into any .NET / Unity project to add license validation.
 *
 * Requirements:
 *   - .NET 6+ (or .NET Standard 2.1 for Unity)
 *   - NuGet: System.Management  (for WMI-based HWID on Windows)
 *   - NuGet: System.Text.Json   (included in .NET 6+; add package for older targets)
 *
 * Unity note: replace System.Management WMI calls with SystemInfo.deviceUniqueIdentifier.
 *
 * Usage:
 *   var validator = new LicenseValidator("https://your-server.com");
 *   ValidationResult result = await validator.ValidateAsync("XXXX-XXXX-XXXX-XXXX");
 *   MessageBox.Show(result.Message);
 *   if (result.Granted) { /* start app * / }
 */

using System;
using System.Management;          // requires System.Management NuGet package
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace TamozaKeyGen
{
    // ─────────────────────────────────────────────────────────────────────────
    // Validation Status Enum
    // ─────────────────────────────────────────────────────────────────────────

    public enum ValidationStatus
    {
        Granted,
        Expired,
        NotYetActive,
        Paused,
        HwidMismatch,
        KeyNotFound,
        AppMismatch,    // Key is not registered for this application name
        Suspicious,     // Granted but flagged — application decides how to handle
        NetworkError,
        ServerError,
        Unknown,
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Result Object
    // ─────────────────────────────────────────────────────────────────────────

    public sealed class ValidationResult
    {
        public ValidationStatus Status          { get; }
        public string           Message         { get; }
        public bool             Granted         { get; }
        public string?          AppName         { get; }
        public string?          OwnerName       { get; }
        public string?          EndDate         { get; }
        public string?          KeyClass        { get; }
        public string?          PermissionLevel { get; }
        public bool             IsSuspicious    { get; }

        internal ValidationResult(
            ValidationStatus status,
            string           message,
            bool             granted,
            string?          appName          = null,
            string?          ownerName        = null,
            string?          endDate          = null,
            string?          keyClass         = null,
            string?          permissionLevel  = null,
            bool             isSuspicious     = false)
        {
            Status          = status;
            Message         = message;
            Granted         = granted;
            AppName         = appName;
            OwnerName       = ownerName;
            EndDate         = endDate;
            KeyClass        = keyClass;
            PermissionLevel = permissionLevel;
            IsSuspicious    = isSuspicious;
        }

        public override string ToString() => Message;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HWID Provider — WMI-based hardware fingerprint
    // ─────────────────────────────────────────────────────────────────────────

    internal static class HardwareIdProvider
    {
        private static string? _cached;
        private static readonly object _lock = new();

        /// <summary>
        /// Returns a stable, SHA-256 hardware fingerprint derived from
        /// the CPU ProcessorId and Motherboard SerialNumber via WMI.
        /// The result is cached for the process lifetime.
        /// </summary>
        public static string GetHardwareId()
        {
            if (_cached is not null)
                return _cached;

            lock (_lock)
            {
                if (_cached is not null)
                    return _cached;

                string cpuId    = QueryWmi("SELECT ProcessorId FROM Win32_Processor",   "ProcessorId");
                string boardSerial = QueryWmi("SELECT SerialNumber FROM Win32_BaseBoard", "SerialNumber");

                // Some OEMs ship placeholder serials — fall back to system UUID
                if (string.IsNullOrWhiteSpace(boardSerial) ||
                    boardSerial.Equals("To Be Filled By O.E.M.", StringComparison.OrdinalIgnoreCase) ||
                    boardSerial.Equals("Default string",         StringComparison.OrdinalIgnoreCase))
                {
                    boardSerial = QueryWmi("SELECT UUID FROM Win32_ComputerSystemProduct", "UUID");
                }

                string raw = $"{cpuId}::{boardSerial}";
                _cached = ComputeSha256Hex(raw);
                return _cached;
            }
        }

        /// <summary>
        /// Executes a WMI query and returns the first value of <paramref name="property"/>.
        /// Returns an empty string on any failure — never throws.
        /// </summary>
        private static string QueryWmi(string wqlQuery, string property)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(wqlQuery);
                using ManagementObjectCollection results = searcher.Get();

                foreach (ManagementObject obj in results)
                    return obj[property]?.ToString()?.Trim() ?? string.Empty;
            }
            catch
            {
                // WMI unavailable or access denied — return empty silently
            }
            return string.Empty;
        }

        private static string ComputeSha256Hex(string input)
        {
            byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
            return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // JSON DTOs (internal)
    // ─────────────────────────────────────────────────────────────────────────

    internal sealed class ValidateRequest
    {
        [JsonPropertyName("key")]      public string  Key     { get; set; } = "";
        [JsonPropertyName("app_name")] public string  AppName { get; set; } = "";
        [JsonPropertyName("hwid")]     public string? Hwid    { get; set; }
        [JsonPropertyName("region")]   public string? Region  { get; set; }
    }

    internal sealed class ValidateResponse
    {
        [JsonPropertyName("valid")]             public bool    Valid           { get; set; }
        [JsonPropertyName("message")]           public string? Message         { get; set; }
        [JsonPropertyName("is_suspicious")]     public bool    IsSuspicious    { get; set; }
        [JsonPropertyName("app_name")]          public string? AppName         { get; set; }
        [JsonPropertyName("owner_name")]        public string? OwnerName       { get; set; }
        [JsonPropertyName("end_date")]          public string? EndDate         { get; set; }
        [JsonPropertyName("key_class")]         public string? KeyClass        { get; set; }
        [JsonPropertyName("permission_level")]  public string? PermissionLevel { get; set; }
    }

    internal sealed class ErrorResponse
    {
        [JsonPropertyName("detail")] public string? Detail { get; set; }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LicenseValidator — main public surface
    // ─────────────────────────────────────────────────────────────────────────

    public sealed class LicenseValidator : IDisposable
    {
        private static readonly JsonSerializerOptions _jsonOptions = new()
        {
            PropertyNameCaseInsensitive = true,
        };

        private readonly HttpClient _http;
        private readonly string     _validateUrl;
        private readonly string     _appName;
        private readonly string     _hwid;
        private bool                _disposed;

        // ── User-facing message map ──
        private static readonly System.Collections.Generic.Dictionary<ValidationStatus, string> Messages = new()
        {
            [ValidationStatus.Granted]      = "Access Granted.",
            [ValidationStatus.Expired]      = "License Expired. Please renew your license to continue.",
            [ValidationStatus.NotYetActive] = "License Not Yet Active. Your license period has not started.",
            [ValidationStatus.Paused]       = "License Suspended. Contact support to reinstate your license.",
            [ValidationStatus.HwidMismatch] = "Hardware ID Mismatch. This license is bound to a different device.",
            [ValidationStatus.AppMismatch]  = "Invalid Application. This license key is not registered for this application.",
            [ValidationStatus.KeyNotFound]  = "Invalid License Key. The key you entered does not exist.",
            [ValidationStatus.Suspicious]   = "Access Granted (activity flagged for review).",
            [ValidationStatus.NetworkError] = "Network Error. Could not reach the license server. Check your connection.",
            [ValidationStatus.ServerError]  = "Server Error. The license server returned an unexpected response.",
            [ValidationStatus.Unknown]      = "Unknown Error. Please try again or contact support.",
        };

        /// <summary>
        /// Initialises the validator.
        /// </summary>
        /// <param name="serverBaseUrl">Base URL of the TamozaKeyGen server (no trailing slash).</param>
        /// <param name="appName">Application name that must match the stored key record.</param>
        /// <param name="timeoutSeconds">HTTP request timeout. Defaults to 10 s.</param>
        public LicenseValidator(string serverBaseUrl, string appName = "App", int timeoutSeconds = 10)
        {
            if (string.IsNullOrWhiteSpace(serverBaseUrl))
                throw new ArgumentException("Server base URL must not be empty.", nameof(serverBaseUrl));

            _validateUrl = serverBaseUrl.TrimEnd('/') + "/api/v1/validate";
            _appName     = appName;
            _hwid        = HardwareIdProvider.GetHardwareId();

            _http = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(timeoutSeconds),
            };
            _http.DefaultRequestHeaders.Accept.Add(
                new MediaTypeWithQualityHeaderValue("application/json"));
        }

        // ──────────────────────────────────────────────────────────────────────
        // Public async validate
        // ──────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Validates <paramref name="licenseKey"/> against the server.
        /// </summary>
        /// <param name="licenseKey">The license key string entered by the user.</param>
        /// <param name="region">Optional ISO region code (e.g. "US") for server-side analytics.</param>
        /// <param name="cancellationToken">Optional cancellation token.</param>
        /// <returns>A <see cref="ValidationResult"/> with a user-friendly message and Granted flag.</returns>
        public async Task<ValidationResult> ValidateAsync(
            string            licenseKey,
            string?           region            = null,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(licenseKey))
                return Make(ValidationStatus.KeyNotFound);

            var payload = new ValidateRequest
            {
                Key     = licenseKey.Trim(),
                AppName = _appName,
                Hwid    = _hwid,
                Region  = region,
            };

            string jsonBody;
            try
            {
                jsonBody = JsonSerializer.Serialize(payload, _jsonOptions);
            }
            catch
            {
                return Make(ValidationStatus.Unknown);
            }

            using var content = new StringContent(jsonBody, Encoding.UTF8, "application/json");

            HttpResponseMessage response;
            try
            {
                response = await _http.PostAsync(_validateUrl, content, cancellationToken)
                                      .ConfigureAwait(false);
            }
            catch (HttpRequestException)
            {
                return Make(ValidationStatus.NetworkError);
            }
            catch (TaskCanceledException)
            {
                return Make(ValidationStatus.NetworkError);
            }

            return await ParseResponseAsync(response, cancellationToken).ConfigureAwait(false);
        }

        // ──────────────────────────────────────────────────────────────────────
        // Synchronous overload (wraps async — use only when async is unavailable)
        // ──────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Blocking synchronous overload of <see cref="ValidateAsync"/>.
        /// Prefer <see cref="ValidateAsync"/> wherever async/await is available.
        /// </summary>
        public ValidationResult Validate(string licenseKey, string? region = null)
            => ValidateAsync(licenseKey, region).GetAwaiter().GetResult();

        // ──────────────────────────────────────────────────────────────────────
        // Response parsing
        // ──────────────────────────────────────────────────────────────────────

        private async Task<ValidationResult> ParseResponseAsync(
            HttpResponseMessage response,
            CancellationToken   ct)
        {
            int code = (int)response.StatusCode;

            if (code == 200)
            {
                ValidateResponse? body = null;
                try
                {
                    string raw = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                    body = JsonSerializer.Deserialize<ValidateResponse>(raw, _jsonOptions);
                }
                catch { /* JSON parse failure → fall through to ServerError */ }

                if (body is null || !body.Valid)
                    return Make(ValidationStatus.ServerError);

                var status = body.IsSuspicious ? ValidationStatus.Suspicious : ValidationStatus.Granted;
                return new ValidationResult(
                    status:          status,
                    message:         Messages[status],
                    granted:         true,
                    appName:         body.AppName,
                    ownerName:       body.OwnerName,
                    endDate:         body.EndDate,
                    keyClass:        body.KeyClass,
                    permissionLevel: body.PermissionLevel,
                    isSuspicious:    body.IsSuspicious
                );
            }

            // Read error detail for differentiated 403 mapping
            string detail = string.Empty;
            try
            {
                string raw = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                var err = JsonSerializer.Deserialize<ErrorResponse>(raw, _jsonOptions);
                detail = (err?.Detail ?? string.Empty).ToLowerInvariant();
            }
            catch { /* ignore */ }

            return code switch
            {
                404 => Make(ValidationStatus.KeyNotFound),

                403 when detail.Contains("expired")     => Make(ValidationStatus.Expired),
                403 when detail.Contains("not yet")     => Make(ValidationStatus.NotYetActive),
                403 when detail.Contains("paused")      => Make(ValidationStatus.Paused),
                403 when detail.Contains("hardware") ||
                         detail.Contains("hwid")        => Make(ValidationStatus.HwidMismatch),
                403 when detail.Contains("application") => Make(ValidationStatus.AppMismatch),
                403                                     => Make(ValidationStatus.Paused),

                400 when detail.Contains("hwid")        => Make(ValidationStatus.HwidMismatch),
                400                                     => Make(ValidationStatus.Unknown),

                >= 500                                  => Make(ValidationStatus.ServerError),
                _                                       => Make(ValidationStatus.Unknown),
            };
        }

        // ──────────────────────────────────────────────────────────────────────
        // Helpers
        // ──────────────────────────────────────────────────────────────────────

        private static ValidationResult Make(ValidationStatus status)
        {
            bool granted = status is ValidationStatus.Granted or ValidationStatus.Suspicious;
            return new ValidationResult(status, Messages[status], granted);
        }

        /// <summary>Returns the hardware fingerprint for the current device (read-only).</summary>
        public string HardwareId => _hwid;

        public void Dispose()
        {
            if (!_disposed)
            {
                _http.Dispose();
                _disposed = true;
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Console entry-point — for standalone testing
    // ─────────────────────────────────────────────────────────────────────────

    internal static class Program
    {
        private static async Task Main(string[] args)
        {
            Console.Write("Server URL [https://your-server.com]: ");
            string serverUrl = Console.ReadLine()?.Trim() ?? "";
            if (string.IsNullOrWhiteSpace(serverUrl))
                serverUrl = "https://your-server.com";

            Console.Write("App name [App]: ");
            string appName = Console.ReadLine()?.Trim() ?? "";
            if (string.IsNullOrWhiteSpace(appName))
                appName = "App";

            Console.Write("License key: ");
            string key = ReadMasked();

            if (string.IsNullOrWhiteSpace(key))
            {
                Console.WriteLine("No key entered. Exiting.");
                Environment.Exit(1);
            }

            using var validator = new LicenseValidator(serverUrl, appName);

            Console.WriteLine($"\n  Detected HWID : {validator.HardwareId[..16]}…");
            Console.WriteLine("  Contacting license server…\n");

            ValidationResult result = await validator.ValidateAsync(key);

            Console.WriteLine(new string('─', 44));
            Console.WriteLine($"  Status  : {result.Status}");
            Console.WriteLine($"  Message : {result.Message}");
            if (result.Granted)
            {
                Console.WriteLine($"  App     : {result.AppName          ?? "—"}");
                Console.WriteLine($"  Owner   : {result.OwnerName        ?? "—"}");
                Console.WriteLine($"  Class   : {result.KeyClass         ?? "—"}");
                Console.WriteLine($"  Perm    : {result.PermissionLevel  ?? "—"}");
                Console.WriteLine($"  Expires : {result.EndDate          ?? "—"}");
            }
            Console.WriteLine(new string('─', 44));

            Environment.Exit(result.Granted ? 0 : 1);
        }

        /// <summary>Reads a password-style line without echoing characters.</summary>
        private static string ReadMasked()
        {
            var sb = new StringBuilder();
            ConsoleKeyInfo key;
            while ((key = Console.ReadKey(intercept: true)).Key != ConsoleKey.Enter)
            {
                if (key.Key == ConsoleKey.Backspace && sb.Length > 0)
                    sb.Remove(sb.Length - 1, 1);
                else if (key.Key != ConsoleKey.Backspace)
                    sb.Append(key.KeyChar);
            }
            Console.WriteLine();
            return sb.ToString();
        }
    }
}
