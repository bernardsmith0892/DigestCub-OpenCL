import md5
import pytest

def test_python_md5_matches_rfc():
    """Check if the Python MD5 function generates the correct digests, according to the RFC."""    
    # From - https://www.rfc-editor.org/rfc/rfc1321
    # MD5 test suite:
    #   ("input_message", "expected_md5_digest")
    rfc_test_cases = [ 
        ("", "d41d8cd98f00b204e9800998ecf8427e"),
        ("a", "0cc175b9c0f1b6a831c399e269772661"),
        ("abc", "900150983cd24fb0d6963f7d28e17f72"),
        ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
        ("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"),
        ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f"),
        ("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "57edf4a22be3c955ac49da2e2107b67a")
    ]
    for msg, rfc_digest in rfc_test_cases:
        calculated_digest = md5.generate_md5_digest(msg.encode('utf-8')).hex()
        assert calculated_digest == rfc_digest, f'Calculated digest does not match RFC digest!\nCalc: {calculated_digest}\nRFC:  {rfc_digest}'

def test_opencl_md5_matches_rfc():
    """Check if the OpenCL MD5 kernel generates the correct digests, according to the RFC."""    
    # From - https://www.rfc-editor.org/rfc/rfc1321
    # MD5 test suite:
    #   ("input_message", "expected_md5_digest")
    rfc_test_cases = [ 
        ("", "d41d8cd98f00b204e9800998ecf8427e"),
        ("a", "0cc175b9c0f1b6a831c399e269772661"),
        ("abc", "900150983cd24fb0d6963f7d28e17f72"),
        ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
        ("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"),
        ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f"),
        ("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "57edf4a22be3c955ac49da2e2107b67a")
    ]

    messages_for_opencl = [msg.encode('utf-8') for msg, _ in rfc_test_cases]
    calculated_digests = md5.generate_digests_with_gpu(messages_for_opencl)
    for i, calculated_digest in enumerate(calculated_digests):
        assert calculated_digest.hex() == rfc_test_cases[i][1], f"Calculated digest for '{rfc_test_cases[i][0]}' does not match RFC digest!\nCalc: {calculated_digest.hex()}\nRFC:  {rfc_test_cases[i][1]}"

def test_opencl_md5_successfully_bruteforces():
    """Check if the OpenCL bruteforce kernel successfully finds the correct password."""    
    # From - https://www.rfc-editor.org/rfc/rfc1321
    # MD5 test suite:
    #   ("password", "md5_digest")
    test_cases = [ 
        ("password", "5f4dcc3b5aa765d61d8327deb882cf99"),
        ("123456", "e10adc3949ba59abbe56e057f20f883e"),
        ("johnny23", "1481a386d88c126fc099c574e58eced9"),
    ]

    wordlist = open('rockyou.txt', 'rb').readlines()
    # Strip newline chars from each test input and generate an MD5 digest for each
    test_passwords = [word.strip() for word in wordlist]

    for test in test_cases:
        result = md5.bruteforce_digests_with_gpu(test_passwords, test[1])
        if result is not None:
            found_password = test_passwords[result].decode('utf-8')
            break
        assert found_password == test[0], f"Discovered password does not match test case!\nFound: {found_password}\nTest Case:  {test[0]}"
