namespace MfpEv2Issue.IssueUi;

internal sealed class SectorKeysDialog : Form
{
    public Dictionary<int, string> Overrides { get; private set; } = new();

    public SectorKeysDialog(string defaultKey, string switchKey, IReadOnlyDictionary<int, string> overrides)
    {
        Text = "Sector AES key overrides";
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(800, 620);
        MinimumSize = new Size(680, 440);
        Font = new Font("Segoe UI", 10);
        var grid = new DataGridView
        {
            Dock = DockStyle.Fill, AllowUserToAddRows = false, AllowUserToDeleteRows = false,
            RowHeadersVisible = false, AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
            EditMode = DataGridViewEditMode.EditOnEnter, AccessibleName = "Per-sector key overrides"
        };
        grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Sector", ReadOnly = true, FillWeight = 15 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Key B address", ReadOnly = true, FillWeight = 25 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Override AES key (blank = default)", FillWeight = 85, MaxInputLength = 32 });
        grid.EditingControlShowing += (_, e) =>
        {
            if (e.Control is not TextBox editor) return;
            editor.MaxLength = 32;
            editor.CharacterCasing = CharacterCasing.Upper;
            editor.KeyPress -= HexKeyTextBox.FilterKeyPress;
            editor.KeyPress += HexKeyTextBox.FilterKeyPress;
        };
        grid.Columns[2].DefaultCellStyle.Font = new Font("Consolas", 10);
        for (int sector = 0; sector < 32; sector++)
            grid.Rows.Add(sector.ToString("D2"), $"{0x4001 + 2 * sector:X4}", overrides.GetValueOrDefault(sector, ""));
        var error = new Label { AutoSize = true, ForeColor = Color.Firebrick, Dock = DockStyle.Top };
        var apply = new Button { Text = "Apply", AutoSize = true };
        var cancel = new Button { Text = "Cancel", AutoSize = true, DialogResult = DialogResult.Cancel };
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, FlowDirection = FlowDirection.RightToLeft };
        buttons.Controls.Add(cancel);
        buttons.Controls.Add(apply);
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(12), RowCount = 4, ColumnCount = 1 };
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.Controls.Add(new Label { Text = "Enter up to 16 hex bytes; missing trailing bytes become zero. Blank rows use the default key.", AutoSize = true });
        layout.Controls.Add(grid);
        layout.Controls.Add(error);
        layout.Controls.Add(buttons);
        Controls.Add(layout);
        CancelButton = cancel;
        apply.Click += (_, _) =>
        {
            grid.EndEdit();
            var entries = Enumerable.Range(0, 32)
                .Where(s => !string.IsNullOrWhiteSpace(grid.Rows[s].Cells[2].Value?.ToString()))
                .ToDictionary(s => s, s => grid.Rows[s].Cells[2].Value!.ToString()!);
            try
            {
                var keys = MifarePlusKeys.CreateUniformKeySet(defaultKey, switchKey, sectorOverrides: entries);
                Overrides = entries.Keys.ToDictionary(s => s, s => Convert.ToHexString(keys[$"SECTOR{s}"]));
                DialogResult = DialogResult.OK;
                Close();
            }
            catch (ArgumentException ex) { error.Text = ex.Message; }
        };
    }
}
