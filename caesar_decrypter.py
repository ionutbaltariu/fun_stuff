"""
Simple Caesar shift decrypter. Gets the most common symbol and tries to match it with space and all the letters from
the alphabet ([a-zA-Z]).
"""


from collections import Counter

def decrypt(encoded_text, key):
  # 1114112 is the number of unicode characters
  return ''.join([chr((ord(x) - key) % 1114112) for x in encoded_text])

def pseudo_smart_brute_force(encoded_text):
  most_common_symbol = max(Counter(encoded_text).items(), key= lambda x: x[1])[0]
  space = [chr(32)]
  big_letters = [chr(65+i) for i in range(26)]
  small_letters = [chr(97+i) for i in range(26)]
  common_chars = space + big_letters + small_letters

  for char in common_chars:
    diff = abs(ord(char) - ord(most_common_symbol))
    decrypted = decrypt(encoded_text, diff)
    print(f"{decrypted} [shift = {ord(char) - ord(most_common_symbol)} -> {most_common_symbol} fata de {char}]")


if __name__ == "__main__":
  pseudo_smart_brute_force("Grk~gtjx{&HGRZGXO[")