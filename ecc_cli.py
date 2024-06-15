import ECC
from cmd2 import Cmd, Cmd2ArgumentParser, with_argparser
import sys

if '--ecc-py-only' not in sys.argv:
    try:
        from Crypto.Cipher import AES
        from base64 import b64encode, b64decode
    except ImportError:
        print("PyCryptodome could not be loaded. Some encryption functions will not work.")
        AES = None
else:
    AES = None
    print("Using ECC.py only. Some encryption functions will not work.")

class ECCCLI(Cmd):

    def __init__(self, space=None, gen=None, key=None):
        super().__init__()
        self.prompt = "ecc> "
        self.intro = "Welcome to the ECC CLI. Type help or ? to list commands."

        self.space = space
        self.gen = gen
        self.key = key

    def do_set_space(self, arg):
        """
        Set or get the elliptic curve space.
        Usage: `set_space p a b` or `set_space curve_name` or `set_space`
        """
        if not arg:
            if self.space is None:
                self.perror("No space specified.")
                return
            print("Space specification:")
            print(f"p: {hex(self.space.p)}")
            print(f"a: {hex(self.space.a)}")
            print(f"b: {hex(self.space.b)}")
            return

        if arg.isdigit():
            p, a, b = map(int, arg.split())
            self.space = ECC.ECSpace(p, a, b)
            if self.space.is_singular():
                self.perror("Singular curve, abort operation.")
                self.space = None
            self.key = None
        else:
            self.space, self.gen = ECC.load_space(arg)
            self.key = None

    def do_set_generator(self, arg):
        """
        Set or get the generator point.
        Usage: `set_generator x y` or `set_generator`
        """
        if not arg:
            if self.gen is None:
                self.perror("No generator point specified.")
                return
            print(f"Generator point: ({hex(self.gen.x)}, {hex(self.gen.y)})")
            print(f"Order: {self.gen.order}")
            return

        if self.space is None:
            self.perror("Space must be set first.")
            return
        x, y = map(int, arg.split())
        self.gen = ECC.ECPoint(x, y, self.space)
        if self.space.is_valid(self.gen):
            self.perror("Invalid generator point, abort operation.")
            self.gen = None
            self.key = None

    def ecdh_get_shared(self):
        """
        Perform an ECDH key exchange.
        """
        if self.space is None or self.gen is None:
            raise ValueError("Space and generator must be set first.")
        
        ecdh = ECC.ECDH(self.space, self.gen)
        key = ecdh.generate()
        ser = key.pub_key.serialize()
        print(f"Public key to send: {ser}")

        ser = input("Enter the other party's public key: ")
        key = ECC.ECPoint.deserialize(ser, self.space)
        shared = ecdh.shared_secret(key)
        return shared
    
    def do_ecdh(self, arg):
        """
        Perform an ECDH key exchange.
        Usage: `ecdh`
        """
        shared = self.ecdh_get_shared().serialize()
        print(f"Shared secret: {shared}")

    def do_ecies(self, arg):
        """
        Use AES encryption with prior ECDH key exchange.
        Usage: `ecies`
        """
        if AES is None:
            self.perror("PyCryptodome is not available.")
            return

        key = self.ecdh_get_shared()
        shift = max(32 - key.x.bit_length(),0)
        key = ((key.x << shift) ^ key.y).to_bytes((key._nbits+7)//8, 'big')[-32:]
        cli = ECCCLI_AES(key)
        cli.cmdloop()
        
def clear_console() -> None:
    print("\033[H\033[J")
    return None

# ---------------------------- AES CLI ----------------------------
encryptArgparser = Cmd2ArgumentParser()
encryptArgparser.add_argument('message', help='The message to encrypt.')
encryptArgparser.add_argument("-f", "--file", help="Encrypt the contents of a file instead of a message.")
encryptArgparser.add_argument("-o", "--output", help="Output the encrypted message to a file instead of the console.")

decryptArgparser = Cmd2ArgumentParser()
decryptArgparser.add_argument('message', help='The message to decrypt.')
decryptArgparser.add_argument("-f", "--file", help="Decrypt the contents of a file instead of a message.")
decryptArgparser.add_argument("-o", "--output", help="Output the decrypted message to a file instead of the console.")

chatArgparser = Cmd2ArgumentParser()
chatArgparser.add_argument('ip', help='The IP address of the other party.')
chatArgparser.add_argument('port', help='The port of the other party.', type=int, default=0xAE5)

class ECCCLI_AES(Cmd):

    def __init__(self, key=None):
        super().__init__()
        self.prompt = "aes> "
        self.intro = "Welcome to the AES CLI. Type help or ? to list commands."
        self.register_postloop_hook(clear_console)

        self.key = key
        self.tag_length = 16
        self.mode = "EAX"

    def do_set_key(self, arg):
        """
        Set or get the AES key.
        Usage: `set_key key` or `set_key`
        """
        if not arg:
            if self.key is None:
                self.perror("No key specified.")
                return
            print(f"Key: {self.key.hex()}")
            return

        self.key = arg.encode()

    def do_set_mode(self, arg):
        """
        Get the AES mode.
        Usage: `set_mode`
        """
        if not arg:
            print(f"Mode: {self.mode}")
            return
        
        self.perror("Mode setting not yet implemented.")

    @with_argparser(encryptArgparser)
    def do_encrypt(self, arg):
        """
        Encrypt a message.
        Usage: `encrypt message [-o output]` or `encrypt -f file [-o output]`
        """

        if arg.file is not None:
            try:
                with open(arg.file, 'r') as f:
                    msg = f.read()
            except FileNotFoundError:
                self.perror("File not found.")
                return
        else:
            msg = arg.message

        cipher = AES.new(self.key, AES.MODE_EAX, mac_len=self.tag_length)
        # 16 bytes nonce, 16 bytes tag, then the ciphertext
        ciphertext, tag = cipher.encrypt_and_digest(msg.encode())
        nonce = cipher.nonce

        if arg.output is not None:
            try:
                with open(arg.output, 'wb') as f:
                    f.write(nonce + tag + ciphertext)
            except FileNotFoundError as e:
                self.perror("Output file could not be opened: " + str(e))
                return
            print(f"Encrypted message written to {arg.output}")
            return

        print("Encrypted message:")
        print(b64encode(nonce + tag + ciphertext).decode())

    @with_argparser(decryptArgparser)
    def do_decrypt(self, arg):
        """
        Decrypt a message.
        Usage: `decrypt message [-o output]` or `decrypt -f file [-o output]`
        """

        if arg.file is not None:
            try:
                with open(arg.file, 'rb') as f:
                    decoded = f.read()
            except FileNotFoundError:
                self.perror("File not found.")
                return
        else:
            decoded = b64decode(arg.message)

        nonce, tag, ciphertext = decoded[:16], decoded[16:32], decoded[32:]
        cipher = AES.new(self.key, AES.MODE_EAX, mac_len=self.tag_length, nonce=nonce)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            self.perror("Decryption verification failed! The message may have been tampered with.")
            return
        
        if arg.output is not None:
            try:
                with open(arg.output, 'wb') as f:
                    f.write(plaintext)
            except FileNotFoundError as e:
                self.perror("Output file could not be opened: " + str(e))
                return
            print(f"Decrypted message written to {arg.output}")
            return
        else:
            print(plaintext.decode())

    @with_argparser(chatArgparser)
    def do_chat(self, arg):
        """
        Start a chat session.
        Usage: `chat ip [port=0xAE5]`
        Quit the chat session with Ctrl+C.
        """
        self.perror("Chat mode not yet implemented.")
        

if __name__ == "__main__":
    sp, gen = ECC.load_space('secp256k1')
    cli = ECCCLI(sp, gen)
    cli.cmdloop()