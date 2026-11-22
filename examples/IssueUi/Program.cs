namespace MfpEv2Issue.IssueUi;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new IssueForm());
    }
}
