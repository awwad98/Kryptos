using SharpToken;
using System.Text;

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

// Wrap SymSpell’s WordSegmentation in a tiny helper
public sealed class WordSegmenter
{
    private readonly SymSpell _sym;

    private WordSegmenter(SymSpell sym)
    {
        _sym = sym;
    }

    public static WordSegmenter? TryCreate(string dictionaryPath, out string message)
    {
        try
        {
            // No autocorrect → maxEditDistance = 0
            int initialCapacity = 82765;
            int maxEditDistanceDictionary = 0;

            var sym = new SymSpell(initialCapacity, maxEditDistanceDictionary);

            int termIndex = 0;
            int countIndex = 1;

            if (!File.Exists(dictionaryPath))
            {
                message =
                    $"[WordSegmentation] Dictionary not found: {dictionaryPath}. " +
                    "Segmentation disabled.";
                return null;
            }

            if (!sym.LoadDictionary(dictionaryPath, termIndex, countIndex))
            {
                message = $"[WordSegmentation] Failed to load dictionary: {dictionaryPath}.";
                return null;
            }

            message = "[WordSegmentation] Dictionary loaded — autocorrect disabled.";
            return new WordSegmenter(sym);
        }
        catch (Exception ex)
        {
            message = $"[WordSegmentation] Error: {ex.Message}. Segmentation disabled.";
            return null;
        }
    }

    public string Segment(string text)
    {
        if (_sym == null || string.IsNullOrEmpty(text))
            return text;

        // Perform segmentation with NO corrections
        var result = _sym.WordSegmentation(
            input: text,
            maxEditDistance: 0,       // No modifications allowed
            maxSegmentationWordLength: 30
        );

        var segmented = result.correctedString ?? text;

        // ✅ Safety check: ensure NO CHARACTER (except spaces) was changed
        var filteredOriginal = new string(text.Where(c => c != ' ').ToArray());
        var filteredSegmented = new string(segmented.Where(c => c != ' ').ToArray());

        if (!string.Equals(filteredOriginal, filteredSegmented, StringComparison.Ordinal))
        {
            // SymSpell attempted correction → reject and return raw
            return text;
        }

        return segmented;
    }
}

public class VigenereResult
{
    public string Key { get; set; } = "";
    public string Plaintext { get; set; } = "";
    public string? PlaintextSegmented { get; set; } // post-processed with SymSpell
    public double Score { get; set; }
}

public class VigenereSolver
{
    private readonly string _ciphertext;
    private readonly string _alphabet;
    private readonly Dictionary<char, int> _alphabetIndex;
    private readonly Scorer _scorer;
    private readonly WordSegmenter? _segmenter;

    public VigenereSolver(string ciphertext, string alphabet, WordSegmenter? segmenter = null)
    {
        _ciphertext = ciphertext;
        _alphabet = alphabet;
        _segmenter = segmenter;
        _alphabetIndex = new Dictionary<char, int>();
        for (int i = 0; i < alphabet.Length; i++) _alphabetIndex[alphabet[i]] = i;
        _scorer = new Scorer();
    }

    // Keyed alphabet builder
    public static string BuildKeyedAlphabet(string baseAlphabet, string keyPhrase)
    {
        if (string.IsNullOrEmpty(keyPhrase)) return baseAlphabet.ToUpperInvariant();
        var seen = new HashSet<char>();
        var outChars = new List<char>();

        foreach (var ch in keyPhrase.ToUpperInvariant())
            if (baseAlphabet.Contains(ch) && seen.Add(ch))
                outChars.Add(ch);

        foreach (var ch in baseAlphabet.ToUpperInvariant())
            if (!seen.Contains(ch))
                outChars.Add(ch);

        return new string(outChars.ToArray());
    }

    // Decrypt with provided key over the keyed alphabet; keep punctuation
    public string DecryptWithKey(string key)
    {
        var plain = new StringBuilder(_ciphertext.Length);
        int keyLen = key.Length;
        int keyPos = 0;

        for (int i = 0; i < _ciphertext.Length; i++)
        {
            char c = _ciphertext[i];
            char cu = char.ToUpperInvariant(c);
            if (!_alphabetIndex.TryGetValue(cu, out int cIndex))
            {
                plain.Append(c);
            }
            else
            {
                char kch = char.ToUpperInvariant(key[keyPos % keyLen]);
                int kIndex = _alphabetIndex[kch];
                int pIndex = (cIndex - kIndex) % _alphabet.Length;
                if (pIndex < 0) pIndex += _alphabet.Length;
                char pch = _alphabet[pIndex];
                if (char.IsLower(c)) pch = char.ToLowerInvariant(pch);
                plain.Append(pch);
                keyPos++;
            }
        }
        return plain.ToString();
    }

    // Extract only letters from ciphertext for Kasiski indexing
    public (string letters, List<int> indices) ExtractAlphabetLetters()
    {
        var sb = new StringBuilder();
        var idx = new List<int>();
        for (int i = 0; i < _ciphertext.Length; i++)
        {
            char cu = char.ToUpperInvariant(_ciphertext[i]);
            if (_alphabetIndex.ContainsKey(cu))
            {
                sb.Append(cu);
                idx.Add(i);
            }
        }
        return (sb.ToString(), idx);
    }

    // Kasiski: find repeated substrings and their start positions (letters-only stream)
    public Dictionary<string, List<int>> FindRepeatedPatterns(int minLen = 3, int maxLen = 8)
    {
        var (lettersOnly, _) = ExtractAlphabetLetters();
        var dict = new Dictionary<string, List<int>>(StringComparer.OrdinalIgnoreCase);
        int n = lettersOnly.Length;
        maxLen = Math.Min(maxLen, Math.Max(0, n / 2));

        for (int L = minLen; L <= maxLen; L++)
        {
            for (int i = 0; i + L <= n; i++)
            {
                var sub = lettersOnly.Substring(i, L);
                if (!dict.TryGetValue(sub, out var list))
                    dict[sub] = list = new List<int>();
                list.Add(i);
            }
        }

        return dict.Where(kv => kv.Value.Count >= 2)
                   .OrderByDescending(kv => kv.Key.Length)
                   .ToDictionary(kv => kv.Key, kv => kv.Value);
    }

    private static List<int> Factors(int x, int maxFactor = 50)
    {
        var res = new List<int>();
        x = Math.Abs(x);
        for (int f = 2; f <= maxFactor && f <= x; f++)
            if (x % f == 0) res.Add(f);
        return res;
    }

    public int[] EstimateKeyLengthsByKasiski(Dictionary<string, List<int>> repeatedPatterns, int maxKeyLenToConsider = 30, int topN = 5)
    {
        var votes = new Dictionary<int, int>();
        foreach (var kv in repeatedPatterns)
        {
            var pos = kv.Value;
            for (int i = 0; i < pos.Count; i++)
                for (int j = i + 1; j < pos.Count; j++)
                {
                    int dist = pos[j] - pos[i];
                    if (dist <= 0) continue;
                    foreach (var f in Factors(dist, maxKeyLenToConsider))
                    {
                        votes.TryGetValue(f, out int cur);
                        votes[f] = cur + 1;
                    }
                }
        }

        if (votes.Count == 0)
            return Array.Empty<int>();

        return votes.OrderByDescending(kv => kv.Value)
                    .ThenBy(kv => kv.Key)
                    .Select(kv => kv.Key)
                    .Take(topN)
                    .ToArray();
    }

    // For a given key length, solve each Caesar subchannel by frequency
    public string AnalyzeKeyForLength(int keyLen)
    {
        var (lettersOnly, _) = ExtractAlphabetLetters();
        var keyChars = new char[keyLen];
        int alphabetLen = _alphabet.Length;
        for (int pos = 0; pos < keyLen; pos++)
        {
            var sb = new StringBuilder();
            for (int i = pos; i < lettersOnly.Length; i += keyLen)
                sb.Append(lettersOnly[i]);

            var group = sb.ToString();
            double bestScore = double.NegativeInfinity;
            char bestKeyLetter = _alphabet[0];

            for (int shift = 0; shift < alphabetLen; shift++)
            {
                var dec = new StringBuilder(group.Length);
                foreach (char c in group)
                {
                    int ci = _alphabetIndex[c];
                    int pi = (ci - shift) % alphabetLen;
                    if (pi < 0) pi += alphabetLen;
                    dec.Append(_alphabet[pi]);
                }
                double score = _scorer.ScorePartial(dec.ToString());
                if (score > bestScore)
                {
                    bestScore = score;
                    bestKeyLetter = _alphabet[shift];
                }
            }
            keyChars[pos] = bestKeyLetter;
        }
        return new string(keyChars);
    }

    // Full attack for candidate lengths; returns results with segmented plaintext if SymSpell is available
    public List<VigenereResult> AttackUsingKasiski(int[] candidateKeyLengths, int topResults = 5, CancellationToken cancellationToken = default)
    {
        var results = new List<VigenereResult>();
        var tried = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var len in candidateKeyLengths)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Console.WriteLine($"\nAnalyzing candidate key length = {len}");

            var key = AnalyzeKeyForLength(len);
            if (tried.Add(key))
                results.Add(ScoreAndSegment(key));

            // quick local tweaks (+/-1 shift per position)
            int aLen = _alphabet.Length;
            var locals = new List<VigenereResult>();
            for (int pos = 0; pos < len; pos++)
            {
                for (int delta = -1; delta <= 1; delta += 2)
                {
                    var k = key.ToCharArray();
                    int cur = _alphabetIndex[char.ToUpperInvariant(k[pos])];
                    int ni = (cur + delta) % aLen; if (ni < 0) ni += aLen;
                    k[pos] = _alphabet[ni];
                    var candKey = new string(k);
                    if (tried.Add(candKey))
                        locals.Add(ScoreAndSegment(candKey));
                }
            }
            results.AddRange(locals.OrderByDescending(r => r.Score).Take(3));
        }

        return results.OrderByDescending(r => r.Score).Take(topResults).ToList();
    }

    private VigenereResult ScoreAndSegment(string key)
    {
        var raw = DecryptWithKey(key);
        var seg = _segmenter?.Segment(raw);
        var score = _scorer.Score(seg ?? raw);
        return new VigenereResult { Key = key, Plaintext = raw, PlaintextSegmented = seg, Score = score };
    }
}

// English scoring (chi-square + light common-word bonus)
public class Scorer
{
    private static readonly double[] EnglishFreq = new double[]
    {
            8.167,1.492,2.782,4.253,12.702,2.228,2.015,6.094,6.966,0.153,
            0.772,4.025,2.406,6.749,7.507,1.929,0.095,5.987,6.327,9.056,
            2.758,0.978,2.360,0.150,1.974,0.074
    };

    private readonly HashSet<string> _common = new(StringComparer.OrdinalIgnoreCase)
        {
            "THE","BE","TO","OF","AND","A","IN","THAT","HAVE","I","IT","FOR","NOT","ON","WITH","HE","AS","YOU","DO","AT","IS","THIS","BUT","BY","FROM"
        };

    public double Score(string plaintext)
    {
        double freq = -ChiSquare(plaintext);
        double words = CommonWordBonus(plaintext) * 20.0;
        double spaces = (plaintext.Count(ch => ch == ' ') / 5.0);
        return freq + words + spaces;
    }

    public double ScorePartial(string partial)
    {
        double c = ChiSquare(partial);
        double lenFactor = Math.Min(1.0, partial.Length / 20.0);
        return -c * lenFactor;
    }

    private double ChiSquare(string text)
    {
        var counts = new double[26];
        int total = 0;
        foreach (var ch in text.ToUpperInvariant())
            if (ch is >= 'A' and <= 'Z') { counts[ch - 'A']++; total++; }

        if (total == 0) return double.PositiveInfinity;

        double chi = 0.0;
        for (int i = 0; i < 26; i++)
        {
            double expected = EnglishFreq[i] * total / 100.0;
            double observed = counts[i];
            double diff = observed - expected;
            chi += diff * diff / (expected > 0 ? expected : 1.0);
        }
        return chi;
    }

    private int CommonWordBonus(string text)
    {
        int m = 0;
        var toks = text.ToUpperInvariant()
                       .Split(new char[] { ' ', ',', '.', ';', ':', '\t', '\r', '\n', '!', '?', '-', '(', ')', '"' },
                              StringSplitOptions.RemoveEmptyEntries);
        foreach (var t in toks)
            if (t.Length > 1 && _common.Contains(t)) m++;
        return m;
    }
}