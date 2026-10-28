using WinAppGuard.Localization;
using WinAppGuard.Models;

namespace WinAppGuard.Forms;

/// <summary>
/// 4.1：流量页的速率曲线（自绘，不引入第三方图表库）。
///
/// 只负责画最近 5 分钟的「入站 / 出站」两条折线：
///   - 数据点由服务端每秒给一个；
///   - 纵轴按当前窗口最大值自适应，三条参考线；
///   - 采样/暂停状态由页面文字说明，图里不重复；
///   - 采集断开时曲线自然留出空隙（值为 0），不做插值，避免伪造数据。
/// </summary>
internal sealed class TrafficChart : Control
{
    private static readonly Color InboundColor = Color.FromArgb(31, 119, 180);
    private static readonly Color OutboundColor = Color.FromArgb(217, 119, 24);

    private long[] _in = Array.Empty<long>();
    private long[] _out = Array.Empty<long>();

    public TrafficChart()
    {
        DoubleBuffered = true;
        ResizeRedraw = true;
        BackColor = SystemColors.Window;
        MinimumSize = new Size(200, 80);
        TabStop = false;
    }

    public void SetSeries(IReadOnlyList<long> inbound, IReadOnlyList<long> outbound)
    {
        var count = Math.Min(inbound.Count, outbound.Count);

        if (count == 0)
        {
            if (_in.Length == 0)
            {
                return;
            }

            _in = Array.Empty<long>();
            _out = Array.Empty<long>();
            Invalidate();
            return;
        }

        if (_in.Length != count)
        {
            _in = new long[count];
            _out = new long[count];
        }

        for (var i = 0; i < count; i++)
        {
            _in[i] = inbound[i];
            _out[i] = outbound[i];
        }

        Invalidate();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);

        var graphics = e.Graphics;
        graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        graphics.Clear(BackColor);

        var left = 8;
        var right = Math.Max(left + 10, ClientSize.Width - 8);
        var top = 8;
        var bottom = Math.Max(top + 10, ClientSize.Height - 8);

        if (right - left < 20 || bottom - top < 20)
        {
            return;
        }

        var max = 1L;

        foreach (var value in _in)
        {
            if (value > max) max = value;
        }

        foreach (var value in _out)
        {
            if (value > max) max = value;
        }

        using var gridPen = new Pen(Color.FromArgb(230, 230, 230));

        using var labelBrush = new SolidBrush(SystemColors.GrayText);
        using var labelFont = new Font("Microsoft YaHei UI", 7.5F);

        for (var i = 0; i <= 2; i++)
        {
            var y = top + (bottom - top) * i / 2;
            graphics.DrawLine(gridPen, left, y, right, y);

            var value = (long)(max * (2 - i) / 2.0);
            var text = TcpConnectionItem.FormatTrafficBytes(value) + "/s";
            var size = graphics.MeasureString(text, labelFont);

            graphics.DrawString(
                text,
                labelFont,
                labelBrush,
                Math.Max(left, right - size.Width - 2),
                Math.Max(top, y - size.Height));
        }

        if (_in.Length < 2)
        {
            using var emptyBrush = new SolidBrush(SystemColors.GrayText);
            using var emptyFont = new Font("Microsoft YaHei UI", 8F);
            var text = Localizer.T("等待流量…");
            var size = graphics.MeasureString(text, emptyFont);
            graphics.DrawString(
                text,
                emptyFont,
                emptyBrush,
                left + (right - left - size.Width) / 2,
                top + (bottom - top - size.Height) / 2);
            return;
        }

        DrawSeries(graphics, _in, top, bottom, left, right, max, InboundColor);
        DrawSeries(graphics, _out, top, bottom, left, right, max, OutboundColor);
    }

    private void DrawSeries(
        Graphics graphics,
        long[] values,
        int top,
        int bottom,
        int left,
        int right,
        long max,
        Color color)
    {
        if (values.Length < 2)
        {
            return;
        }

        var points = new PointF[values.Length];
        var step = (right - left) / (float)(values.Length - 1);

        for (var i = 0; i < values.Length; i++)
        {
            var ratio = max <= 0 ? 0 : Math.Clamp(values[i] / (double)max, 0, 1);
            points[i] = new PointF(left + step * i, bottom - (float)(ratio * (bottom - top)));
        }

        using var pen = new Pen(color, 1.6F);
        graphics.DrawLines(pen, points);
    }
}
