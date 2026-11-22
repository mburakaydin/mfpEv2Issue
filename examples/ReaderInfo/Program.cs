using PCSC;

try
{
    using var context = ContextFactory.Instance.Establish(SCardScope.System);
    var readers = context.GetReaders();
    if (readers.Length == 0) Console.WriteLine("No PC/SC readers found.");
    foreach (var reader in readers) Console.WriteLine(reader);
    return 0;
}
catch (Exception error)
{
    Console.Error.WriteLine($"Unable to enumerate readers: {error.Message}");
    return 1;
}
