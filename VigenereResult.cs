namespace Kryptos;

public class VigenereResult
{
    public string Key { get; set; } = "";
    public string Plaintext { get; set; } = "";
    public string? PlaintextSegmented { get; set; } // post-processed with SymSpell
    public double Score { get; set; }
}