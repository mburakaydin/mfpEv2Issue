using PCSC;

namespace MfpEv2Issue.IssueUi;

internal sealed class IssueForm : Form
{
    private readonly ComboBox readers = new() { DropDownStyle = ComboBoxStyle.DropDownList, Dock = DockStyle.Fill };
    private readonly Button refresh = new() { Text = "Refresh", AutoSize = true };
    private readonly Button issue = new() { Text = "Issue card", AutoSize = true, Enabled = false };
    private readonly Button clear = new() { Text = "Clear logs", AutoSize = true };
    private readonly Button save = new() { Text = "Save logs…", AutoSize = true };
    private readonly ComboBox startMode = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 190 };
    private readonly CheckBox raw = new() { Text = "Raw commands after activation", Checked = true, AutoSize = true };
    private readonly HexKeyTextBox sectorKey = new()
    {
        Text = new string('F', 32), Dock = DockStyle.Fill,
        Font = new Font("Consolas", 10), AccessibleName = "Sector AES key"
    };
    private readonly HexKeyTextBox switchKey = new()
    {
        Text = new string('0', 32), Dock = DockStyle.Fill,
        Font = new Font("Consolas", 10), AccessibleName = "9007 switch key"
    };
    private readonly Dictionary<string, TextBox> controlKeyInputs = new()
    {
        ["MASTER"] = NewControlKeyInput("9000 master key"),
        ["CONF"] = NewControlKeyInput("9001 configuration key"),
        ["L3SWITCH"] = NewControlKeyInput("9003 SL3 switch key"),
        ["L3SECTORSWITCH"] = NewControlKeyInput("9006 SL3 sector switch key")
    };
    private readonly Button editOverrides = new() { Text = "Per-sector overrides…", AutoSize = true };
    private readonly Label overridesSummary = new() { Text = "Overrides: none", AutoSize = true };
    private Dictionary<int, string> sectorOverrides = new();
    private readonly TextBox logs = new()
    {
        Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both,
        WordWrap = false, Dock = DockStyle.Fill, Font = new Font("Consolas", 10),
        BackColor = Color.FromArgb(248, 249, 251)
    };
    private readonly Label status = new() { Text = "Loading readers…", AutoSize = true, Dock = DockStyle.Fill };
    private readonly Label uid = new() { Text = "UID: —", AutoSize = true, Font = new Font("Consolas", 11, FontStyle.Bold), Margin = new Padding(0, 8, 0, 0) };
    private bool busy;

    public IssueForm()
    {
        Text = "MIFARE Plus EV2 · 2KB issuer";
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(1080, 920);
        MinimumSize = new Size(900, 800);
        AutoScaleMode = AutoScaleMode.Dpi;
        Font = new Font("Segoe UI", 10);

        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(18), ColumnCount = 1, RowCount = 8 };
        for (int i = 0; i < 8; i++)
            layout.RowStyles.Add(new RowStyle(i == 6 ? SizeType.Percent : SizeType.AutoSize, i == 6 ? 100 : 0));
        layout.Controls.Add(new Label { Text = "MIFARE Plus EV2 issuing", AutoSize = true, Font = new Font(Font, FontStyle.Bold), Margin = new Padding(0, 0, 0, 8) });
        layout.Controls.Add(new Label
        {
            Text = "2KB · sectors 0–31 · SL1SL3Mix\nPlace one card on the reader and keep it there until issuing finishes.",
            AutoSize = true, Margin = new Padding(0, 0, 0, 14)
        });
        var readerRow = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 4, Margin = Padding.Empty };
        readerRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        readerRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        readerRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        readerRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        readerRow.Controls.Add(new Label { Text = "Reader", AutoSize = true, Anchor = AnchorStyles.Left });
        readerRow.Controls.Add(readers);
        readerRow.Controls.Add(refresh);
        readerRow.Controls.Add(issue);
        readerRow.Controls.Add(uid, 0, 1);
        readerRow.SetColumnSpan(uid, 4);
        layout.Controls.Add(readerRow);
        startMode.Items.AddRange(new object[] { "Auto (activation SAK)", "Start from SL0", "Continue from SL1" });
        startMode.SelectedIndex = 0;
        var options = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Margin = new Padding(0, 8, 0, 8) };
        options.Controls.Add(new Label { Text = "Flow", AutoSize = true, Margin = new Padding(0, 6, 8, 0) });
        options.Controls.Add(startMode);
        options.Controls.Add(raw);
        layout.Controls.Add(options);
        var keyPanel = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 2, Margin = new Padding(0, 0, 0, 10) };
        keyPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        keyPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        keyPanel.Controls.Add(new Label { Text = "Default sector AES key", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 0);
        keyPanel.Controls.Add(sectorKey, 1, 0);
        int keyRow = 1;
        foreach (var (name, input) in controlKeyInputs)
        {
            keyPanel.Controls.Add(new Label { Text = input.AccessibleName, AutoSize = true, Anchor = AnchorStyles.Left }, 0, keyRow);
            keyPanel.Controls.Add(input, 1, keyRow++);
        }
        keyPanel.Controls.Add(new Label { Text = "9007 mixed-mode switch key", AutoSize = true, Anchor = AnchorStyles.Left }, 0, keyRow);
        keyPanel.Controls.Add(switchKey, 1, keyRow++);
        keyPanel.Controls.Add(editOverrides, 0, keyRow++);
        keyPanel.SetColumnSpan(editOverrides, 2);
        keyPanel.Controls.Add(overridesSummary, 0, keyRow++);
        keyPanel.SetColumnSpan(overridesSummary, 2);
        var keyHelp = new Label
        {
            Text = "Up to 16 hex bytes per key; short entries are padded on the right with zeroes.\nSL0 writes sector A/B and control keys. Continue from SL1 authenticates with sector Key B and 9007.",
            AutoSize = true, Margin = new Padding(0, 6, 0, 0)
        };
        keyPanel.Controls.Add(keyHelp, 0, keyRow);
        keyPanel.SetColumnSpan(keyHelp, 2);
        layout.Controls.Add(keyPanel);
        var logBar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Margin = new Padding(0, 0, 0, 6) };
        logBar.Controls.Add(clear);
        logBar.Controls.Add(save);
        layout.Controls.Add(logBar);
        layout.Controls.Add(logs);
        status.Margin = new Padding(0, 10, 0, 0);
        layout.Controls.Add(status);
        Controls.Add(layout);

        Shown += async (_, _) => await RefreshReadersAsync();
        refresh.Click += async (_, _) => await RefreshReadersAsync();
        readers.SelectedIndexChanged += (_, _) =>
        {
            issue.Enabled = !busy && readers.SelectedItem is string;
            uid.Text = "UID: —";
        };
        issue.Click += async (_, _) => await IssueAsync();
        clear.Click += (_, _) => logs.Clear();
        save.Click += (_, _) => SaveLogs();
        editOverrides.Click += (_, _) =>
        {
            using var dialog = new SectorKeysDialog(sectorKey.Text, switchKey.Text, sectorOverrides);
            if (dialog.ShowDialog(this) != DialogResult.OK) return;
            sectorOverrides = dialog.Overrides;
            UpdateOverrideSummary();
        };
        FormClosing += (_, e) =>
        {
            if (busy) { e.Cancel = true; status.Text = "Wait for the current reader operation to finish before closing."; }
        };
    }

    private static HexKeyTextBox NewControlKeyInput(string name) => new()
    {
        Text = new string('0', 32), Dock = DockStyle.Fill,
        Font = new Font("Consolas", 10), AccessibleName = name
    };

    private void UpdateOverrideSummary() => overridesSummary.Text = sectorOverrides.Count == 0
        ? "Overrides: none" : $"Overrides: sectors {string.Join(", ", sectorOverrides.Keys.Order())}";

    private void SetBusy(bool value)
    {
        busy = value;
        refresh.Enabled = readers.Enabled = startMode.Enabled = raw.Enabled = !value;
        sectorKey.Enabled = switchKey.Enabled = editOverrides.Enabled = !value;
        foreach (var input in controlKeyInputs.Values) input.Enabled = !value;
        issue.Enabled = !value && readers.SelectedItem is string;
        UseWaitCursor = value;
    }

    private void Log(string message) => logs.AppendText($"[{DateTimeOffset.Now:HH:mm:ss.fff}] {message}{Environment.NewLine}");

    private async Task RefreshReadersAsync()
    {
        var selected = readers.SelectedItem as string;
        uid.Text = "UID: —";
        SetBusy(true);
        try
        {
            var names = await Task.Run(() =>
            {
                using var context = ContextFactory.Instance.Establish(SCardScope.System);
                return context.GetReaders();
            });
            readers.Items.Clear();
            readers.Items.AddRange(names);
            if (names.Length > 0)
            {
                int preferred = Array.IndexOf(names, selected);
                if (preferred < 0)
                    preferred = Array.FindIndex(names, name => name.Contains("PICC", StringComparison.OrdinalIgnoreCase));
                readers.SelectedIndex = Math.Max(0, preferred);
            }
            status.Text = names.Length > 0 ? "Ready. Select a reader and place a card." : "No readers found. Connect a reader, then click Refresh.";
            Log($"Found {names.Length} reader(s).");
        }
        catch (Exception ex)
        {
            readers.Items.Clear();
            status.Text = "Reader discovery failed.";
            Log($"ERROR: {ex.Message}");
        }
        finally { SetBusy(false); }
    }

    private async Task IssueAsync()
    {
        if (readers.SelectedItem is not string readerName || busy) return;
        Dictionary<string, byte[]> keys;
        try
        {
            // Validate and snapshot the inputs before opening a reader or changing card state.
            var controls = controlKeyInputs.ToDictionary(pair => pair.Key, pair => pair.Value.Text);
            controls["MIXSECTORSWITCH"] = switchKey.Text;
            keys = MifarePlusKeys.CreateKeySet(sectorKey.Text, controls, sectorOverrides);
        }
        catch (ArgumentException ex)
        {
            status.Text = "Invalid key input. No card operation started.";
            Log($"Key validation: {ex.Message}");
            return;
        }
        int mode = startMode.SelectedIndex;
        bool useRaw = raw.Checked;
        SetBusy(true);
        uid.Text = "UID: reading…";
        status.Text = "Issuing… keep the card on the reader.";
        Log($"Opening reader: {readerName}");
        Log($"Flow: {startMode.Text}; post-activation transport: {(useRaw ? "raw" : "wrapped")}");
        Log(overridesSummary.Text);
        var progress = new Progress<string>(Log);
        var uidProgress = new Progress<string>(value => uid.Text = $"UID: {value}");
        try
        {
            await Task.Run(() =>
            {
                void Report(string text) => ((IProgress<string>)progress).Report(text);
                using var channel = new PcscMifarePlusChannel(readerName);
                var ctrl = new MifarePlusController(channel);
                var cardUid = ctrl.GetCardInformation().Uid;
                if (cardUid is null || cardUid.Length is not (4 or 7 or 10))
                    throw new MifarePlusException("Reader did not return a valid 4, 7, or 10-byte UID.");
                var uidHex = Convert.ToHexString(cardUid);
                ((IProgress<string>)uidProgress).Report(uidHex);
                Report($"Card UID: {uidHex}");
                switch (mode)
                {
                    case 0: CardPerso.Issue2KbSL1SL3MixFromCurrentState(ctrl, keys, Report, useRaw); break;
                    case 1: CardPerso.Issue2KbSL1SL3Mix(ctrl, keys, Report, useRaw); break;
                    case 2: CardPerso.Continue2KbSL1ToSL1SL3Mix(ctrl, keys, Report, useRaw); break;
                    default: throw new InvalidOperationException("Select an issuing flow.");
                }
            });
            status.Text = "Complete. All 32 sectors processed. See per-sector results.";
            Log("SUCCESS: sectors switched or accepted as already switched (0x09). See sector results above.");
        }
        catch (Exception ex)
        {
            if (uid.Text == "UID: reading…") uid.Text = "UID: unavailable";
            status.Text = "Issuing stopped. See logs for the failed stage.";
            Log($"ERROR ({ex.GetType().Name}): {ex.Message}");
            Log("Earlier successful card changes remain applied. Existing SL1 cards need SectorSwitch enabled and keys matching the inputs.");
        }
        finally { SetBusy(false); }
    }

    private void SaveLogs()
    {
        using var dialog = new SaveFileDialog { Filter = "Text logs (*.txt)|*.txt", FileName = $"mfp-issue-{DateTime.Now:yyyyMMdd-HHmmss}.txt" };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        try { File.WriteAllText(dialog.FileName, logs.Text); }
        catch (Exception ex) { Log($"Could not save logs: {ex.Message}"); }
    }
}
