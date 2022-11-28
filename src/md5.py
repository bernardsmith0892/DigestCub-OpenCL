import math
from typing import List, Optional, Tuple
from numpy.typing import NDArray
from fixedint.aliases import MutableUInt32 as u32

import pyopencl as cl
import pyopencl.array
import numpy as np

def generate_md5_digest(msg: bytes) -> bytes:
    """Python implementation of the MD5 hashing function in accordance with RFC 1321.

    Args:
        msg (bytes): Message to process.

    Returns:
        bytes: Resulting MD5 digest.
    """
    # 3.1 Step 1. Append Padding Bits
    padded_msg = msg + b'\x80'
    while len(padded_msg) % 64 != 56:
        padded_msg += b'\x00'
    
    # 3.2 Step 2. Append Length
    padded_msg += (len(msg) * 8).to_bytes(8, 'little')
    M = [u32.from_bytes(padded_msg[i:i+4], 'little') for i in range(0, len(padded_msg), 4)]

    # 3.3 Step 3. Initialize MD Buffer
    A, B, C, D = u32(0x67452301), u32(0xefcdab89), u32(0x98badcfe), u32(0x10325476)

    # 3.4 Step 4. Process Message in 16-Word Blocks
    # ** define four auxiliary functions **
    def F(X, Y, Z): return (X & Y) | ((~X) & Z)
    def G(X, Y, Z): return (X & Z) | (Y & (~Z))
    def H(X, Y, Z): return X ^ Y ^ Z
    def I(X, Y, Z): return Y ^ (X | (~Z))

    # Let T[i] denote the i-th element of the table, which is equal to the integer part of 4294967296 times abs(sin(i)), where i is in radians.
    T = [u32(2**32 * abs(math.sin(i))) for i in range(0, 65)]

    # Process each 16-word block.
    N = len(M)
    for i in range(N // 16):
        # Copy block i into X.
        X = [u32(M[i * 16 + j]) for j in range(16)]
        
        # Save A as AA, B as BB, C as CC, and D as DD.
        AA, BB, CC, DD = u32(A), u32(B), u32(C), u32(D)

        # Round 1.
        # Let [abcd k s i] denote the operation
        #  a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s).
        def FF(a, b, c, d, k, s, i):
            a += F(b, c, d) + X[k] + T[i]
            a = (((a) << (s)) | ((a) >> (32-(s))))
            return a + b
        # Do the following 16 operations.
        AA = FF(AA, BB, CC, DD,  0,  7,  1)
        DD = FF(DD, AA, BB, CC,  1, 12,  2)
        CC = FF(CC, DD, AA, BB,  2, 17,  3)
        BB = FF(BB, CC, DD, AA,  3, 22,  4)
        AA = FF(AA, BB, CC, DD,  4,  7,  5)
        DD = FF(DD, AA, BB, CC,  5, 12,  6)
        CC = FF(CC, DD, AA, BB,  6, 17,  7)
        BB = FF(BB, CC, DD, AA,  7, 22,  8)
        AA = FF(AA, BB, CC, DD,  8,  7,  9)
        DD = FF(DD, AA, BB, CC,  9, 12, 10)
        CC = FF(CC, DD, AA, BB, 10, 17, 11)
        BB = FF(BB, CC, DD, AA, 11, 22, 12)
        AA = FF(AA, BB, CC, DD, 12,  7, 13)
        DD = FF(DD, AA, BB, CC, 13, 12, 14)
        CC = FF(CC, DD, AA, BB, 14, 17, 15)
        BB = FF(BB, CC, DD, AA, 15, 22, 16)

        # Round 2.
        # Let [abcd k s i] denote the operation
        #  a = b + ((a + G(b,c,d) + X[k] + T[i]) <<< s).
        def GG(a, b, c, d, k, s, i):
            a += G(b,c,d) + X[k] + T[i]
            a = (((a) << (s)) | ((a) >> (32-(s))))
            return a + b
        # Do the following 16 operations.
        AA = GG(AA, BB, CC, DD,  1,  5, 17)
        DD = GG(DD, AA, BB, CC,  6,  9, 18)
        CC = GG(CC, DD, AA, BB, 11, 14, 19)
        BB = GG(BB, CC, DD, AA,  0, 20, 20)
        AA = GG(AA, BB, CC, DD,  5,  5, 21)
        DD = GG(DD, AA, BB, CC, 10,  9, 22)
        CC = GG(CC, DD, AA, BB, 15, 14, 23)
        BB = GG(BB, CC, DD, AA,  4, 20, 24)
        AA = GG(AA, BB, CC, DD,  9,  5, 25)
        DD = GG(DD, AA, BB, CC, 14,  9, 26)
        CC = GG(CC, DD, AA, BB,  3, 14, 27)
        BB = GG(BB, CC, DD, AA,  8, 20, 28)
        AA = GG(AA, BB, CC, DD, 13,  5, 29)
        DD = GG(DD, AA, BB, CC,  2,  9, 30)
        CC = GG(CC, DD, AA, BB,  7, 14, 31)
        BB = GG(BB, CC, DD, AA, 12, 20, 32)

        # Round 3.
        # Let [abcd k s t] denote the operation
        #     a = b + ((a + H(b,c,d) + X[k] + T[i]) <<< s).
        def HH(a, b, c, d, k, s, i):
            a += H(b,c,d) + X[k] + T[i]
            a = (((a) << (s)) | ((a) >> (32-(s))))
            return a + b
        # Do the following 16 operations.
        AA = HH(AA, BB, CC, DD,  5,  4, 33)
        DD = HH(DD, AA, BB, CC,  8, 11, 34)
        CC = HH(CC, DD, AA, BB, 11, 16, 35)
        BB = HH(BB, CC, DD, AA, 14, 23, 36)
        AA = HH(AA, BB, CC, DD,  1,  4, 37)
        DD = HH(DD, AA, BB, CC,  4, 11, 38)
        CC = HH(CC, DD, AA, BB,  7, 16, 39)
        BB = HH(BB, CC, DD, AA, 10, 23, 40)
        AA = HH(AA, BB, CC, DD, 13,  4, 41)
        DD = HH(DD, AA, BB, CC,  0, 11, 42)
        CC = HH(CC, DD, AA, BB,  3, 16, 43)
        BB = HH(BB, CC, DD, AA,  6, 23, 44)
        AA = HH(AA, BB, CC, DD,  9,  4, 45)
        DD = HH(DD, AA, BB, CC, 12, 11, 46)
        CC = HH(CC, DD, AA, BB, 15, 16, 47)
        BB = HH(BB, CC, DD, AA,  2, 23, 48)

        # Round 4.
        # Let [abcd k s t] denote the operation
        #     a = b + ((a + I(b,c,d) + X[k] + T[i]) <<< s).
        def II(a, b, c, d, k, s, i):
            a += I(b,c,d) + X[k] + T[i]
            a = (a << s) | (a >> (32-s))
            return a + b
        # Do the following 16 operations.
        AA = II(AA, BB, CC, DD,  0,  6, 49)
        DD = II(DD, AA, BB, CC,  7, 10, 50)
        CC = II(CC, DD, AA, BB, 14, 15, 51)
        BB = II(BB, CC, DD, AA,  5, 21, 52)
        AA = II(AA, BB, CC, DD, 12,  6, 53)
        DD = II(DD, AA, BB, CC,  3, 10, 54)
        CC = II(CC, DD, AA, BB, 10, 15, 55)
        BB = II(BB, CC, DD, AA,  1, 21, 56)
        AA = II(AA, BB, CC, DD,  8,  6, 57)
        DD = II(DD, AA, BB, CC, 15, 10, 58)
        CC = II(CC, DD, AA, BB,  6, 15, 59)
        BB = II(BB, CC, DD, AA, 13, 21, 60)
        AA = II(AA, BB, CC, DD,  4,  6, 61)
        DD = II(DD, AA, BB, CC, 11, 10, 62)
        CC = II(CC, DD, AA, BB,  2, 15, 63)
        BB = II(BB, CC, DD, AA,  9, 21, 64)

        # Then perform the following additions. (That is increment each
        # of the four registers by the value it had before this block
        # was started.)
        A += AA
        B += BB
        C += CC
        D += DD

    return A.to_bytes(4, byteorder='little') \
         + B.to_bytes(4, byteorder='little') \
         + C.to_bytes(4, byteorder='little') \
         + D.to_bytes(4, byteorder='little')


def prepare_message_length_buffers(messages: List[bytes]) -> Tuple[NDArray[np.ubyte], NDArray[np.uint8]]:
    """Prepares a list of messages for use in the OpenCL kernel. Truncates any messages that are longer than or equal to 120 bytes long---MD5 appends the length to the last 8 bytes. 

    Returns:
        Tuple[np.ndarray[np.ubyte], np.ndarray[np.uint32]]: Tuple containing the message_buffer and lengths_buffer
    """    
    padded_message_buffer = bytearray(len(messages) * 128)
    lengths = []
    for i, msg in enumerate(messages):
        # Truncate any message longer than or equal to 120 bytes
        if (len(msg) >= 120):
            msg = msg[:120]
        # Add this message to the buffer, zero-padded up to 128 bytes
        padded_message_buffer[i*128: i*128 + 128] = msg + bytes(128 - len(msg)) 
        # Add the original length of the buffer to the lengths buffer
        lengths.append(len(msg))
    
    # Convert the lists into numpy arrays and return
    message_buffer = np.frombuffer(padded_message_buffer, dtype=np.ubyte)
    lengths_buffer = np.array(lengths, dtype=np.uint32)
    return message_buffer, lengths_buffer

def generate_digests_with_gpu(messages: List[bytes], *, platform_id: int=0, device_id: int=0) -> List[bytes]:
    """Generate an MD5 digest for each provided message.

    Args:
        messages (List[bytes]): Messages to generate digests for.
        platform_id (int, optional): ID of the desired OpenCL platform to use. Defaults to 0.
        device_id (int, optional): ID of the desired OpenCL device to use. Defaults to 0.

    Returns:
        List[bytes]: MD5 digests created from the messages.
    """
    
    # Setup OpenCL platform and context
    platforms = cl.get_platforms()
    device = platforms[platform_id].get_devices()[device_id]
    ctx = cl.Context(
            dev_type=cl.device_type.GPU,
            properties=[(cl.context_properties.PLATFORM, platforms[platform_id])])

    # Create command queue and compile kernel
    queue = cl.CommandQueue(ctx, properties=cl.command_queue_properties.PROFILING_ENABLE)
    program = cl.Program(ctx, open('src/md5.cl').read()).build()
    kernel = program.generate_md5_digests

    # Prepare input and output memory buffers
    messages_host, lengths_host = prepare_message_length_buffers(messages) 
    messages_dev = cl.array.to_device(queue, messages_host)
    lengths_dev = cl.array.to_device(queue, lengths_host)
    results_dev = cl.array.zeros(queue, len(messages) * 4, dtype=np.uint32)

    # Execute the kernel
    event = kernel(queue, (len(messages),), None, messages_dev.data, lengths_dev.data, results_dev.data)
    queue.finish()

    # Convert the results into a list of 128-bit byte-arrays and return
    results = results_dev.get()
    digests = []
    for i in range(0, len(messages) * 4, 4):
        digests.append(
            results[i].tobytes()
          + results[i + 1].tobytes()
          + results[i + 2].tobytes()
          + results[i + 3].tobytes()
        )
    return digests

def bruteforce_digests_with_gpu(test_messages: List[bytes], target_digest: bytes, *, workgroup_size: int=None, platform_id: int=0, device_id: int=0) -> Optional[np.uint32]:
    """Check if any of the given messages matches the target digest.

    Args:
        test_messages (List[bytes]): Messages to test for a match.
        target_digest (bytes): The digest a message needs to successfully match on.
        workgroup_size (int, optional): OpenCL workgroup size. Defaults to half of the device's max workgroup size.
        platform_id (int, optional): ID of the desired OpenCL platform to use. Defaults to 0.
        device_id (int, optional): ID of the desired OpenCL device to use. Defaults to 0.

    Returns:
        Optional[np.uint32]: The index of the matching message. If no match found, then None.
    """    
    
    # TODO: Refactor so the context and kernel is only created once
    platforms = cl.get_platforms()
    device = platforms[platform_id].get_devices()[device_id]
    ctx = cl.Context(
            dev_type=cl.device_type.GPU,
            properties=[(cl.context_properties.PLATFORM, platforms[platform_id])])

    queue = cl.CommandQueue(ctx, properties=cl.command_queue_properties.PROFILING_ENABLE)
    program = cl.Program(ctx, open('src/md5.cl').read()).build()
    kernel = program.bruteforce_md5_digests

    if workgroup_size is None:
        workgroup_size = device.max_work_group_size // 2
    elif workgroup_size > device.max_work_group_size:
        raise(MemoryError(f"The workgroup size ({workgroup_size}) is larger than the device's maximum size! ({device.max_work_group_size})"))
    assert len(test_messages) % workgroup_size == 0

    # TODO: Refactor so this padding function is more efficient
    messages_host, lengths_host = prepare_message_length_buffers(test_messages) 
    messages_dev = cl.array.to_device(queue, messages_host)
    lengths_dev = cl.array.to_device(queue, lengths_host)
    results_dev = cl.array.zeros(queue, (1,), dtype=np.uint32)
    
    target_host = np.frombuffer(int(target_digest, 16).to_bytes(16, byteorder='big'), dtype=np.uint32)
    target_vec = cl.cltypes.make_uint4(target_host[0], target_host[1], target_host[2], target_host[3])

    event = kernel(queue, (len(test_messages),), (workgroup_size,), messages_dev.data, lengths_dev.data, target_vec, results_dev.data)
    queue.finish()

    results = results_dev.get()
    if results[0] != 0:
        return results[0] - 1
    else:
        return None 

def main():
    # hash_to_break = '5f4dcc3b5aa765d61d8327deb882cf99' # password
    hash_to_break = '9a69ad706500bcd5c649bc5a51ea30a8' # buddykey
    # hash_to_break = 'e10adc3949ba59abbe56e057f20f883e' # 123456
    
    step_size = 2**16
    wordlist = open('rockyou.txt', 'rb').readlines()
    for i in range(0, len(wordlist), step_size):
        # Strip newline chars from each test input and generate an MD5 digest for each
        test_passwords = [word.strip() for word in wordlist[i: i+step_size]]
        result = bruteforce_digests_with_gpu(test_passwords, hash_to_break, workgroup_size=1024)
        if result is not None:
            password = test_passwords[result].decode('utf-8')
            print(f"Password found!\n{password}")
            return
            
        # result = generate_digests_with_gpu(test_passwords, hash_to_break, workgroup_size=256)
        # # Test if any of the resulting digests match the target
        # for i, digest in enumerate(digests):
        #     if digest.hex() == hash_to_break:
        #         password = test_passwords[i].decode('utf-8')
        #         print(f"Password found!\n{password}:{digest.hex()}")
        #         return

if __name__ == '__main__':
    main()