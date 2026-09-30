using Dtls.Core;
using Microsoft.Extensions.DependencyInjection.Extensions;

// Service registration lives in the namespace of IServiceCollection, as the framework's own does, so it
// is found without a using directive.
#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;

#pragma warning restore IDE0130

/// <summary>Registers Dtls.Core with a service collection.</summary>
public static class DtlsServiceCollectionExtensions
{
    /// <summary>
    /// Adds <see cref="DtlsConnectionFactory"/>, which makes connections with the application's logger
    /// factory, time provider and configured options.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddDtls(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        _ = services.AddOptions();
        services.TryAddSingleton<DtlsConnectionFactory>();
        return services;
    }

    /// <summary>
    /// Adds <see cref="DtlsConnectionFactory"/> and configures the client options of a name.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="name">The options' name.</param>
    /// <param name="configure">Configures the options.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddDtlsClient(
        this IServiceCollection services,
        string name,
        Action<DtlsClientConnectionOptions> configure
    )
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(configure);
        return services.AddDtls().Configure(name, configure);
    }

    /// <summary>
    /// Adds <see cref="DtlsConnectionFactory"/> and configures the server options of a name.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="name">The options' name.</param>
    /// <param name="configure">Configures the options.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddDtlsServer(
        this IServiceCollection services,
        string name,
        Action<DtlsServerConnectionOptions> configure
    )
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(configure);
        return services.AddDtls().Configure(name, configure);
    }
}
