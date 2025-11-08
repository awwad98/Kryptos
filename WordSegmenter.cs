namespace Kryptos;

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