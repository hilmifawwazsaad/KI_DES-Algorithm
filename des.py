# Nama      : Hilmi Fawwaz Sa'ad
# NRP       : 5025221103
# Kelas     : Keamanan Informasi (B)
# Program   : DES Algorithm

# Basic Terminology
# Plaintext = Original Message
# Ciphertext = Coded Message
# Encrypt = Convert Plaintext to Ciphertext
# Decrypt = Recovering Plaintext from Ciphertext
# Cipher = Algorithm for transforming plaintext to ciphertext
# Key = Info used in cipher known only to sender/receiver 

# Hexadecimal to Binary Conversion and Binary to Hexadecimal Conversion
def convert_hexbin(s, direction="hex2bin"):
       map_hexbin = {
       '0': "0000", '1': "0001", '2': "0010", '3': "0011",
       '4': "0100", '5': "0101", '6': "0110", '7': "0111",
       '8': "1000", '9': "1001", 'A': "1010", 'B': "1011",
       'C': "1100", 'D': "1101", 'E': "1110", 'F': "1111"
       }
       map_binhex = {v:k for k,v in map_hexbin.items()}
       
       result = ""
       
       if direction == "hex2bin":
              for i in s:
                     result = result + map_hexbin[i]
       elif direction == "bin2hex":
              for i in s:
                     result = result + map_binhex[i]
       return result

def convert_bindec(s, direction="bin2dec"):
       if direction == "bin2dec":
              binary = s
              decimal = 0
              i = 0
              
              while binary != 0:
                     dec = binary % 10
                     decimal = decimal + dec * pow(2, i)
                     binary = binary // 10
                     i += 1
              return decimal
       
       elif direction == "dec2bin":
              decimal = s
              binary = ""
              
              while decimal != 0:
                     binary = str(decimal % 2) + binary
                     decimal = decimal // 2
              return binary

def xor(x, y):
       ans = ""
       for i in range(len(x)):
              if x[i] == y[i]:
                     ans = ans + "0"
              else:
                     ans = ans + "1"
       return ans

def permute(k, arr, n):
       permuted_k = ""
       for i in range(n):
              permuted_k += k[arr[i]-1]
       return permuted_k

def pad_plaintext(plaintext):
       padding_len = 8 - (len(plaintext) % 8)
       padding = chr(padding_len) * padding_len
       return plaintext + padding

def remove_padding(plaintext):
       padding_len = ord(plaintext[-1])
       
       if padding_len < 1 or padding_len > 8:
              raise ValueError("Invalid padding detected!")
       
       if plaintext[-padding_len:] != chr(padding_len) * padding_len:
              raise ValueError("Invalid padding detected!")
       
       return plaintext[:-padding_len]

def key_schedule(bin_key):
       round_keys = []
       left = bin_key[:28]
       right = bin_key[28:]
       shift_table = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

       for round_number, shift in enumerate(shift_table):
              left = left[shift:] + left[:shift]
              right = right[shift:] + right[:shift]
              round_key = left + right
              print(f"Debug: Key for round {round_number + 1}: {round_key[:48]}")

              round_keys.append(round_key[:48]) 

       return round_keys

def sbox_substitution(right_xor):
       substituted = ""
       for j in range(0, 48, 6):
              row = int(right_xor[j] + right_xor[j + 5], 2)
              col = int(right_xor[j + 1:j + 5], 2)
              sbox_value = s_box[j // 6][row][col]
              print(f"Debug: S-box output for block {j // 6}: {sbox_value}")
              substituted += format(sbox_value, '04b')
       return substituted
       
# Initializing the Initial Permutation Table (IP)
init_perm = [58, 50, 42, 34, 26, 18, 10, 2,
              60, 52, 44, 36, 28, 20, 12, 4,
              62, 54, 46, 38, 30, 22, 14, 6,
              64, 56, 48, 40, 32, 24, 16, 8,
              57, 49, 41, 33, 25, 17, 9, 1,
              59, 51, 43, 35, 27, 19, 11, 3,
              61, 53, 45, 37, 29, 21, 13, 5,
              63, 55, 47, 39, 31, 23, 15, 7]

# Expansion D-box Table (E-box)
e_box = [32, 1, 2, 3, 4, 5, 4, 5,
       6, 7, 8, 9, 8, 9, 10, 11,
       12, 13, 12, 13, 14, 15, 16, 17,
       16, 17, 18, 19, 20, 21, 20, 21,
       22, 23, 24, 25, 24, 25, 26, 27,
       28, 29, 28, 29, 30, 31, 32, 1]

# Straight Permutation (P-box)
p_box = [16, 7, 20, 21,
       29, 12, 28, 17,
       1, 15, 23, 26,
       5, 18, 31, 10,
       2, 8, 24, 14,
       32, 27, 3, 9,
       19, 13, 30, 6,
       22, 11, 4, 25]

# Substitution Boxes
s_box = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
       [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
       [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
       [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

       [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
       [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
       [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
       [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

       [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
       [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
       [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
       [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

       [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
       [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
       [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
       [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

       [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
       [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
       [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
       [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

       [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
       [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
       [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
       [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

       [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
       [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
       [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
       [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

       [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
       [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
       [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
       [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

# Initializing the Final Permutation Table (FP)
final_perm = [40, 8, 48, 16, 56, 24, 64, 32,
              39, 7, 47, 15, 55, 23, 63, 31,
              38, 6, 46, 14, 54, 22, 62, 30,
              37, 5, 45, 13, 53, 21, 61, 29,
              36, 4, 44, 12, 52, 20, 60, 28,
              35, 3, 43, 11, 51, 19, 59, 27,
              34, 2, 42, 10, 50, 18, 58, 26,
              33, 1, 41, 9, 49, 17, 57, 25]

def des_encrypt(plaintext, key):
       if len(key) != 8:
              raise ValueError("Key harus 8 karakter")
       
       plaintext = pad_plaintext(plaintext)
       bin_plaintext = ''.join(format(ord(x), '08b') for x in plaintext)
       bin_key = ''.join(format(ord(x), '08b') for x in key)

       permuted_plaintext = permute(bin_plaintext, init_perm, 64)

       left = permuted_plaintext[:32]
       right = permuted_plaintext[32:]

       round_keys = key_schedule(bin_key)

       for i in range(16):
              right_expanded = permute(right, e_box, 48)
              right_xor = xor(right_expanded, round_keys[i])
              substituted = sbox_substitution(right_xor)
              permuted_substituted = permute(substituted, p_box, 32)
              left, right = right, xor(left, permuted_substituted)
       combined = left + right
       cipher_text_bin = permute(combined, final_perm, 64)
       cipher_text_hex = hex(int(cipher_text_bin, 2))[2:].upper()

       return cipher_text_hex


# DES decryption with additional debug output
def des_decrypt(ciphertext, key):
       if len(key) != 8:
              raise ValueError("Key harus 8 karakter")
       
       bin_ciphertext = bin(int(ciphertext, 16))[2:].zfill(64)
       bin_key = ''.join(format(ord(x), '08b') for x in key)

       permuted_ciphertext = permute(bin_ciphertext, init_perm, 64)
       print("Debug: After initial permutation:", permuted_ciphertext)

       left = permuted_ciphertext[:32]
       right = permuted_ciphertext[32:]
       print("Debug: Initial left and right:", left, right)

       round_keys = key_schedule(bin_key)
       print("Debug: Generated round keys")

       round_keys.reverse()
       
       for i in range(16):
              right_expanded = permute(right, e_box, 48)
              print(f"Debug: Round {16-i}, right expanded:", right_expanded)
              right_xor = xor(right_expanded, round_keys[i])
              print(f"Debug: Round {16-i}, right XOR:", right_xor)
              substituted = sbox_substitution(right_xor)
              print(f"Debug: Round {16-i}, after S-box:", substituted)
              permuted_substituted = permute(substituted, p_box, 32)
              print(f"Debug: Round {16-i}, after P-box:", permuted_substituted)
              left, right = right, xor(left, permuted_substituted)
              print(f"Debug: Round {16-i}, new left and right:", left, right)

       combined = left + right
       print("Debug: Combined left and right before final permutation:", combined)
       plain_text_bin = permute(combined, final_perm, 64)
       print("Debug: After final permutation (plain text in binary):", plain_text_bin)
       plain_text = ''
       for i in range(0, 64, 8):
              byte = plain_text_bin[i:i + 8]
              char = chr(int(byte, 2))
              print(f"Binary segment {i//8}: {byte} -> ASCII: {char}")
              plain_text += char

       print("Debug: Decrypted binary before removing padding:", plain_text)
       try:
              return remove_padding(plain_text)
       except ValueError:
              print("Padding error detected, returning unpadded text.")
              return plain_text

# Main function to test encryption and decryption
if __name__ == "__main__":
       plaintext = "ABCDEFGH"
       key = "12345678"

       print("Plaintext:", plaintext)
       print("Key:", key)

       encrypt = des_encrypt(plaintext, key)
       print("Encrypted Text:", encrypt)

       decrypt = des_decrypt(encrypt, key)
       print("Decrypted Text:", decrypt)

