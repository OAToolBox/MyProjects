from googletrans import Translator
import sys

def translate_text(text, src_lang, dest_lang):
    translator = Translator()
    try:
        translation = translator.translate(text, src=src_lang, dest=dest_lang)
        return translation.text
    except Exception as e:
        return f"Translation error: {str(e)}. Input was src='{src_lang}', dest='{dest_lang}', text='{text}'"

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python translate_script.py <source_lang> <target_lang> <text>")
        sys.exit(1)

    source_lang = sys.argv[1]
    target_lang = sys.argv[2]
    text = sys.argv[3]

    translated_text = translate_text(text, source_lang, target_lang)

    sys.stdout.reconfigure(encoding='utf-8')
    print(translated_text)
