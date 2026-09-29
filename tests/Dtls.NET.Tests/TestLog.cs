using System.Text;
using Microsoft.Extensions.Logging;

namespace Dtls.NET.Tests;

// Collects what connections log, at every level, to print when a test fails.
internal sealed class TestLog : ILoggerFactory, ILogger
{
    private readonly StringBuilder _lines = new();

    public void AddProvider(ILoggerProvider provider) { }

    public ILogger CreateLogger(string categoryName) => this;

    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter
    )
    {
        lock (_lines)
        {
            _ = _lines.Append(logLevel).Append(' ').AppendLine(formatter(state, exception));
            if (exception is not null)
            {
                _ = _lines.AppendLine(exception.Message);
            }
        }
    }

    public override string ToString()
    {
        lock (_lines)
        {
            return _lines.ToString();
        }
    }

    public void Dispose() { }
}
