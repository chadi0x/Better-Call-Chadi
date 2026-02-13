import logging
import itertools
import os
import random

logger = logging.getLogger(__name__)

class WordlistService:
    def __init__(self, download_folder):
        self.download_folder = download_folder
        if not os.path.exists(self.download_folder):
            os.makedirs(self.download_folder)

    def generate_wordlist(self, options):
        """
        options: {
            'charset': ['lower', 'upper', 'digits', 'symbols'],
            'min_len': int,
            'max_len': int,
            'pattern': str (optional),
            'base_words': list (optional),
            'leetspeak': bool
        }
        """
        try:
            filename = f"wordlist_{random.randint(1000,9999)}.txt"
            filepath = os.path.join(self.download_folder, filename)
            
            chars = ""
            if 'lower' in options.get('charset', []): chars += "abcdefghijklmnopqrstuvwxyz"
            if 'upper' in options.get('charset', []): chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            if 'digits' in options.get('charset', []): chars += "0123456789"
            if 'symbols' in options.get('charset', []): chars += "!@#$%^&*()_+-=[]{}|;':,./<>?"

            base_words = options.get('base_words', [])
            leet_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}

            with open(filepath, 'w') as f:
                # 1. Base Word Mutations
                if base_words:
                    for word in base_words:
                        word = word.strip()
                        if not word: continue
                        f.write(word + "\n")
                        
                        # Leetspeak
                        if options.get('leetspeak'):
                            leet_word = "".join([leet_map.get(c.lower(), c) for c in word])
                            if leet_word != word:
                                f.write(leet_word + "\n")
                        
                        # Simple Append (Year, Digits)
                        for i in range(2020, 2030):
                            f.write(f"{word}{i}\n")
                        for i in range(10):
                            f.write(f"{word}{i}\n")
                            f.write(f"{word}{i}!\n")

                # 2. Pattern Generation (if pattern provided)
                # Simple syntax: @ = char, # = digit
                pattern = options.get('pattern')
                if pattern:
                    # Very basic pattern logic for demo (replace # with 0-9)
                    # For a robust generator, we'd use product.
                    # Let's do a simple recursive replacement for '#' and '@'
                    self._generate_pattern(f, pattern, ['0123456789', 'abcdefghijklmnopqrstuvwxyz'])
                    
                # 3. Brute Force (Combinations) - LIMIT TO SAFETY TO AVOID DOS
                # If they select brute force without base words, warn or limit.
                if not base_words and not pattern:
                    min_len = int(options.get('min_len', 1))
                    max_len = int(options.get('max_len', 1))
                    
                    # Safety Cap: 100k lines if brute forcing to prevent container freeze
                    count = 0
                    if not chars: chars = "abcdefghijklmnopqrstuvwxyz0123456789" # Fallback
                    
                    for r in range(min_len, max_len + 1):
                        for p in itertools.product(chars, repeat=r):
                            f.write("".join(p) + "\n")
                            count += 1
                            if count > 50000: break # Hard limit for demo
                        if count > 50000: break

            # Return preview
            with open(filepath, 'r') as f:
                preview = [next(f).strip() for _ in range(20)]
            
            return {
                "filename": filename,
                "download_url": f"/api/python/api/engineer/wordlist/download/{filename}",
                "preview": preview,
                "count": "50,000+ (Capped)" if not base_words and not pattern else "Generated Successfully"
            }

        except Exception as e:
            logger.error(f"Wordlist generation failed: {e}")
            raise e

    def _generate_pattern(self, file_handle, current_pattern, charsets):
        # charsets[0] = digits, charsets[1] = letters
        # Naive implementation for # and @
        if '#' not in current_pattern and '@' not in current_pattern:
            file_handle.write(current_pattern + "\n")
            return

        if '#' in current_pattern:
            idx = current_pattern.find('#')
            for d in charsets[0]:
                new_pat = current_pattern[:idx] + d + current_pattern[idx+1:]
                self._generate_pattern(file_handle, new_pat, charsets)
            return

        if '@' in current_pattern:
            idx = current_pattern.find('@')
            for c in charsets[1]:
                new_pat = current_pattern[:idx] + c + current_pattern[idx+1:]
                self._generate_pattern(file_handle, new_pat, charsets)
            return
