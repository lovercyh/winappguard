namespace WinAppGuard.Forms;

public sealed partial class MainForm
{
    /// <summary>5.9：注册所有可见页刷新。后台通知定时器不在这里。</summary>
    private void RegisterPageRefresh()
    {
        _uiScheduler = new UiRefreshScheduler(
            () => SuppressBackgroundServices || !_runtimeInitialized);

        new ConnectionsPage(this).Register(_uiScheduler);
        new AuditPage(this).Register(_uiScheduler);
        new DnsPage(this).Register(_uiScheduler);
        new TrafficPage(this).Register(_uiScheduler);
        new AntiScanPage(this).Register(_uiScheduler);
        new LanPage(this).Register(_uiScheduler);
        new Ipv6Page(this).Register(_uiScheduler);
        new NameResolutionPage(this).Register(_uiScheduler);
        new DnsSecurityPage(this).Register(_uiScheduler);
        new ConfigIntegrityPage(this).Register(_uiScheduler);
        new IdsPage(this).Register(_uiScheduler);
        new NetworkDetectionPage(this).Register(_uiScheduler);
    }

    private sealed class ConnectionsPage : PageBase
    {
        private readonly MainForm _owner;

        internal ConnectionsPage(MainForm owner)
            : base("connections", AutoRefreshIntervalMs)
        {
            _owner = owner;
        }

        internal override bool IsVisible
            => _owner._tabControl.SelectedTab == _owner._tabConnections;

        internal override bool IsAutoRefreshEnabled
            => _owner._autoRefreshCheckBox.Checked;

        internal override Task RefreshAsync()
            => _owner.RefreshConnectionsAsync();
    }

    private sealed class AuditPage : PageBase
    {
        private readonly MainForm _owner;

        internal AuditPage(MainForm owner)
            : base("audit", AuditRefreshIntervalMs)
        {
            _owner = owner;
        }

        internal override bool IsVisible
            => _owner._tabControl.SelectedTab == _owner._tabAudit;

        internal override bool IsAutoRefreshEnabled
            => _owner._auditAutoRefreshCheckBox.Checked;

        internal override Task RefreshAsync()
        {
            _owner.RefreshAudit();
            return Task.CompletedTask;
        }
    }

    private sealed class DnsPage : PageBase
    {
        private readonly MainForm _owner;

        internal DnsPage(MainForm owner)
            : base("dns", DnsRefreshIntervalMs)
        {
            _owner = owner;
        }

        internal override bool IsVisible
            => _owner._tabControl.SelectedTab == _owner._tabDns;

        internal override bool IsAutoRefreshEnabled
            => _owner._dnsAutoRefreshCheckBox.Checked;

        internal override Task RefreshAsync()
            => _owner.RefreshDnsAsync();
    }

    private sealed class TrafficPage : PageBase
    {
        private readonly MainForm _owner;

        internal TrafficPage(MainForm owner)
            : base("traffic", TrafficRefreshIntervalMs)
        {
            _owner = owner;
        }

        internal override bool IsVisible
            => _owner._tabControl.SelectedTab == _owner._tabTraffic;

        internal override bool IsAutoRefreshEnabled
            => _owner._trafficAutoRefreshCheckBox.Checked;

        internal override Task RefreshAsync()
            => _owner.RefreshTrafficAsync();
    }

    private sealed class AntiScanPage : PageBase
    {
        private readonly MainForm _owner;

        internal AntiScanPage(MainForm owner)
            : base("antiscan", AntiScanRefreshIntervalMs)
        {
            _owner = owner;
        }

        internal override bool IsVisible
            => _owner.IsProtectionTab(_owner._tabScan);

        internal override Task RefreshAsync()
            => _owner.RefreshAntiScanAsync();
    }

    private sealed class LanPage : PageBase
    {
        private readonly MainForm _owner;

        internal LanPage(MainForm owner)
            : base("lan", LanRefreshIntervalMs)
        {
            _owner = owner;
        }

        internal override bool IsVisible
            => _owner.IsLanIpv4Tab;

        internal override bool IsAutoRefreshEnabled
            => _owner._lanAutoRefreshCheckBox.Checked;

        internal override Task RefreshAsync()
            => _owner.RefreshLanAsync();
    }

    private sealed class Ipv6Page : PageBase
    {
        private readonly MainForm _owner;

        internal Ipv6Page(MainForm owner)
            : base("ipv6", Ipv6RefreshIntervalMs)
        {
            _owner = owner;
        }

        internal override bool IsVisible
            => _owner.IsLanIpv6Tab;

        internal override bool IsAutoRefreshEnabled
            => _owner._ipv6AutoRefreshCheckBox.Checked;

        internal override Task RefreshAsync()
            => _owner.RefreshIpv6Async();
    }

    private sealed class NameResolutionPage : PageBase
    {
        private readonly MainForm _owner;

        internal NameResolutionPage(MainForm owner)
            : base("name-resolution", NameRefreshIntervalMs)
        {
            _owner = owner;
        }

        internal override bool IsVisible
            => _owner.IsLanNameTab;

        internal override bool IsAutoRefreshEnabled
            => _owner._nameAutoRefreshCheckBox.Checked;

        internal override Task RefreshAsync()
            => _owner.RefreshNameAsync();
    }

    private sealed class DnsSecurityPage : PageBase
    {
        private readonly MainForm _owner;

        internal DnsSecurityPage(MainForm owner)
            : base("dns-security", DnsSecurityRefreshIntervalMs)
        {
            _owner = owner;
        }

        internal override bool IsVisible
            => _owner.IsProtectionTab(_owner._tabDnsSecurity);

        internal override bool IsAutoRefreshEnabled
            => _owner._dnsSecAutoRefreshCheckBox.Checked;

        internal override Task RefreshAsync()
            => _owner.RefreshDnsSecurityAsync();
    }

    private sealed class ConfigIntegrityPage : PageBase
    {
        private readonly MainForm _owner;

        internal ConfigIntegrityPage(MainForm owner)
            : base("config-integrity", ConfigRefreshIntervalMs)
        {
            _owner = owner;
        }

        internal override bool IsVisible
            => _owner.IsProtectionTab(_owner._tabConfig);

        internal override bool IsAutoRefreshEnabled
            => _owner._configAutoRefreshCheckBox.Checked;

        internal override Task RefreshAsync()
            => _owner.RefreshConfigAsync();
    }

    private sealed class IdsPage : PageBase
    {
        private readonly MainForm _owner;

        internal IdsPage(MainForm owner)
            : base("ids", IdsRefreshIntervalMs)
        {
            _owner = owner;
        }

        internal override bool IsVisible
            => _owner.IsProtectionTab(_owner._tabIds);

        internal override Task RefreshAsync()
            => _owner.RefreshIdsAsync();
    }

    private sealed class NetworkDetectionPage : PageBase
    {
        private readonly MainForm _owner;

        internal NetworkDetectionPage(MainForm owner)
            : base("network-detection", NetworkDetectionRefreshIntervalMs)
        {
            _owner = owner;
        }

        internal override bool IsVisible
            => _owner._tabControl.SelectedTab == _owner._tabNetworkDetection;

        internal override bool IsAutoRefreshEnabled
            => _owner._ndAutoRefreshCheckBox.Checked;

        internal override Task RefreshAsync()
        {
            _owner.RefreshNetworkDetection();
            return Task.CompletedTask;
        }
    }
}
