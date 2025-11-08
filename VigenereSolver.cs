using System.Text;

namespace Kryptos;

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