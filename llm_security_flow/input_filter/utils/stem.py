from nltk.stem.snowball import SnowballStemmer


_RU = SnowballStemmer("russian")
_EN = SnowballStemmer("english")


def stem_ru(word: str) -> str:
    return _RU.stem(word.lower())


def stem_en(word: str) -> str:
    return _EN.stem(word.lower())