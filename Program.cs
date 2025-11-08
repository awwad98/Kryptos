namespace Kryptos;

internal class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("Vigenère Solver with Kasiski + Word Segmentation (Keyed alphabet)\n");

        Console.Write("Ciphertext (paste): ");
        var ciphertext = Console.ReadLine() ?? "";

        Console.Write("Base alphabet (default A-Z) press Enter to use default: ");
        var baseAlphabetInput = Console.ReadLine();
        var baseAlphabet = string.IsNullOrWhiteSpace(baseAlphabetInput)
            ? "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            : baseAlphabetInput.ToUpperInvariant();

        Console.Write("Keyed-alphabet keyphrase (optional): ");
        var keyedPhrase = (Console.ReadLine() ?? "").ToUpperInvariant();

        var alphabet = VigenereSolver.BuildKeyedAlphabet(baseAlphabet, keyedPhrase);
        Console.WriteLine($"\nUsing alphabet: {alphabet}\n");

        // ---- SymSpell setup (for inserting spaces in the final output) ----
        // You need a frequency dictionary file (e.g., frequency_dictionary_en_82_765.txt).
        // Put it next to the exe, or paste an absolute path when asked.
        Console.Write("Path to SymSpell dictionary file (Enter to try ./frequency_dictionary_en_82_765.txt): ");
        var dictPath = Console.ReadLine();
        if (string.IsNullOrWhiteSpace(dictPath))
            dictPath = System.IO.Path.Combine(AppContext.BaseDirectory, "frequency_dictionary_en_82_765.txt");

        var wordSeg = WordSegmenter.TryCreate(dictPath, out string segInitMsg);
        Console.WriteLine(segInitMsg);

        var solver = new VigenereSolver(ciphertext, alphabet, wordSeg);

        // ---- Kasiski / repetition analysis to estimate key lengths ----
        var repeats = solver.FindRepeatedPatterns(minLen: 3, maxLen: 8);

        if (repeats.Count > 0)
        {
            Console.WriteLine("Found repeated substrings (sample):");
            foreach (var kv in repeats.Take(10))
                Console.WriteLine($"'{kv.Key}' at positions: {string.Join(",", kv.Value)}");
        }
        else
        {
            Console.WriteLine("No repeated substrings found with current settings.");
        }

        var candidateKeyLens = solver.EstimateKeyLengthsByKasiski(repeats, maxKeyLenToConsider: 20, topN: 8);
        Console.WriteLine("\nCandidate key lengths (ranked): " + (candidateKeyLens.Length == 0 ? "(none)" : string.Join(", ", candidateKeyLens)));

        Console.Write("Try these candidate lengths? (y/N): ");
        var yn = (Console.ReadLine() ?? "").Trim().ToLowerInvariant();
        if (yn != "y")
        {
            Console.Write("Enter max key length to analyze (e.g., 6): ");
            if (!int.TryParse(Console.ReadLine(), out int maxLen) || maxLen < 1) maxLen = 6;
            candidateKeyLens = Enumerable.Range(1, Math.Min(12, maxLen)).ToArray();
        }

        Console.Write("How many top results to show (default 5): ");
        if (!int.TryParse(Console.ReadLine(), out int topN) || topN < 1) topN = 5;

        var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (s, e) => { cts.Cancel(); e.Cancel = true; };

        var results = solver.AttackUsingKasiski(candidateKeyLens, topResults: topN, cancellationToken: cts.Token);

        Console.WriteLine($"\nTop {topN} results:");
        int idx = 1;
        foreach (var r in results.OrderByDescending(x => x.Score).Take(topN))
        {
            Console.WriteLine($"\n[{idx++}] Key='{r.Key}' Score={r.Score:F2}");
            Console.WriteLine("--------- Segmented (readable) ---------");
            Console.WriteLine(r.PlaintextSegmented ?? r.Plaintext);
            Console.WriteLine("--------------- Raw --------------------");
            Console.WriteLine(r.Plaintext);
        }

        Console.WriteLine("\nDone.");
    }
}

