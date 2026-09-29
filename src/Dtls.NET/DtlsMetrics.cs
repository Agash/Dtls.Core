using System.Diagnostics.Metrics;

namespace Dtls.NET;

// The library's instruments, on a meter named "Dtls.NET" as System.Net names its own: listen with
// MeterListener, dotnet-counters or OpenTelemetry's AddMeter("Dtls.NET"). Nothing secret is recorded.
internal static class DtlsMetrics
{
    public const string MeterName = "Dtls.NET";

    private static readonly Meter s_meter = new(MeterName);

    public static Histogram<double> HandshakeDuration { get; } =
        s_meter.CreateHistogram<double>(
            "dtls.handshake.duration",
            "s",
            "How long DTLS handshakes took, by version, role and outcome."
        );

    public static Counter<long> Retransmissions { get; } =
        s_meter.CreateCounter<long>(
            "dtls.retransmissions",
            "{flight}",
            "Handshake flights sent again."
        );

    public static Counter<long> RecordsDropped { get; } =
        s_meter.CreateCounter<long>(
            "dtls.records.dropped",
            "{record}",
            "Records dropped: malformed, replayed, from an unknown epoch or not authentic."
        );

    public static Counter<long> ApplicationRecordsDropped { get; } =
        s_meter.CreateCounter<long>(
            "dtls.application_records.dropped",
            "{record}",
            "Application data dropped because a receive queue was full."
        );
}
