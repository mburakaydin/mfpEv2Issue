namespace MfpEv2Issue.IssueUi;

internal sealed class HexKeyTextBox : TextBox
{
    public HexKeyTextBox()
    {
        MaxLength = 32;
        CharacterCasing = CharacterCasing.Upper;
    }

    internal static void FilterKeyPress(object? sender, KeyPressEventArgs e)
    {
        if (!char.IsControl(e.KeyChar) && !Uri.IsHexDigit(e.KeyChar)) e.Handled = true;
    }

    protected override void OnKeyPress(KeyPressEventArgs e)
    {
        FilterKeyPress(this, e);
        base.OnKeyPress(e);
    }

    protected override void OnLeave(EventArgs e)
    {
        try { Text = MifarePlusKeys.NormalizeAesKeyHex(Text); }
        catch (ArgumentException) { } // Leave incomplete byte pairs visible; Issue validates before opening a reader.
        base.OnLeave(e);
    }

    protected override void WndProc(ref Message m)
    {
        const int wmPaste = 0x0302;
        if (m.Msg == wmPaste)
        {
            if (!Clipboard.ContainsText()) return;
            var pasted = new string(Clipboard.GetText().Where(c => !char.IsWhiteSpace(c)).ToArray());
            if (pasted.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) pasted = pasted[2..];
            // Reject invalid/oversized pastes instead of silently truncating a key.
            if (pasted.Any(c => !Uri.IsHexDigit(c)) || TextLength - SelectionLength + pasted.Length > 32)
            {
                System.Media.SystemSounds.Beep.Play();
                return;
            }
            SelectedText = pasted.ToUpperInvariant();
            return;
        }
        base.WndProc(ref m);
    }
}
