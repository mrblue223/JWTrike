# core/cracker.py
import jwt
import itertools
import threading
from tqdm import tqdm
from queue import Queue

class JWTCracker:
    def __init__(self):
        self.found = False
        self.result = None
    
    def crack(self, token, wordlist=None, brute_force=False, min_length=1, 
              max_length=8, charset=None, compress=False):
        """Crack JWT secret"""
        
        if brute_force:
            return self._brute_force(token, min_length, max_length, charset, compress)
        else:
            return self._dictionary_attack(token, wordlist, compress)
    
    def _dictionary_attack(self, token, wordlist_path, compress):
        """Dictionary attack"""
        
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            words = [line.strip() for line in f]
        
        # Try common algorithms
        algorithms = ['HS256', 'HS384', 'HS512']
        
        for word in tqdm(words, desc="Testing secrets"):
            for alg in algorithms:
                try:
                    if compress:
                        # Try with compression
                        decoded = jwt.decode(token, word, algorithms=[alg], options={'verify_exp': False})
                    else:
                        decoded = jwt.decode(token, word, algorithms=[alg], options={'verify_exp': False})
                    return {"found": True, "secret": word, "algorithm": alg}
                except jwt.InvalidSignatureError:
                    continue
                except Exception:
                    continue
        
        return {"found": False, "secret": None}
    
    def _brute_force(self, token, min_len, max_len, charset, compress):
        """Brute force attack"""
        
        total_combinations = sum(len(charset) ** i for i in range(min_len, max_len + 1))
        
        with tqdm(total=total_combinations, desc="Brute forcing") as pbar:
            for length in range(min_len, max_len + 1):
                for combo in itertools.product(charset, repeat=length):
                    if self.found:
                        return self.result
                    
                    secret = ''.join(combo)
                    
                    # Try common algorithms
                    for alg in ['HS256', 'HS384', 'HS512']:
                        try:
                            decoded = jwt.decode(token, secret, algorithms=[alg], options={'verify_exp': False})
                            self.found = True
                            self.result = {"found": True, "secret": secret, "algorithm": alg}
                            return self.result
                        except jwt.InvalidSignatureError:
                            continue
                        except Exception:
                            continue
                    
                    pbar.update(1)
        
        return {"found": False, "secret": None}