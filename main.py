from datetime import datetime
import math
import os
from pathlib import Path
import random
import string
import wv_proto2_pb2
import hashlib
from Crypto.PublicKey import RSA

# load company names from samples.txt file
company_names = open("samples.txt", "r").read().split("\n")

SERIAL_NUMBER_LENGTH = 16
PUBLIC_KEY_LENGTH = 270
TIMESTAMP_LENGTH = 10
SYSTEM_ID_LENGTH = 4

archs = ["armeabi-v7a", "arm64-v8a", "x86", "x86_64"]


def get_random_company_name():
    return random.choice(company_names)


def generate_bytes(n):
    return random.randbytes(n)


def random_number(n):
    range_start = 10**(n-1)
    range_end = (10**n)-1
    return random.randint(range_start, range_end)


def random_number_in_range(s, e):
    range_start = 10**(s-1)
    range_end = (10**e)-1
    return random.randint(range_start, range_end)


def random_timestamp():
    # random date between 1/1/2000 and now
    return random.randrange(946746000, math.floor(datetime.now().timestamp()))


def get_random_string(n):
    return ''.join(random.choices(string.ascii_uppercase + string.digits + string.ascii_lowercase, k=n))


def get_random_string_in_range(n):
    return ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(n))


def get_random_arch():
    return random.choice(archs)


def generate_build_info(company, model_name, version):
    return f"{company}/{model_name}/{model_name}:{version}/{random_number(TIMESTAMP_LENGTH)}:user/release-keys"


def generate():
    # print("Generating Client ID Blob...")

    device_certificate = wv_proto2_pb2.DeviceCertificate()
    device_certificate.Type = 2
    device_certificate.SerialNumber = generate_bytes(SERIAL_NUMBER_LENGTH)
    device_certificate.CreationTimeSeconds = random_timestamp()
    device_certificate.PublicKey = generate_bytes(PUBLIC_KEY_LENGTH)
    device_certificate.SystemId = random_number(SYSTEM_ID_LENGTH)
    device_certificate.TestDeviceDeprecated = 0
    device_certificate.ServiceId = b''
    # print(f"System ID: {device_certificate.SystemId}")

    device_certificate_signature = hashlib.sha256()
    device_certificate_signature.update(device_certificate.SerializeToString())

    signer_device_certificate = wv_proto2_pb2.DeviceCertificate()
    signer_device_certificate.Type = 1
    signer_device_certificate.SerialNumber = generate_bytes(
        SERIAL_NUMBER_LENGTH)
    signer_device_certificate.CreationTimeSeconds = random_timestamp()
    signer_device_certificate.PublicKey = generate_bytes(PUBLIC_KEY_LENGTH)
    signer_device_certificate.SystemId = device_certificate.SystemId

    signer_device_certificate_signature = hashlib.sha256()
    signer_device_certificate_signature.update(
        signer_device_certificate.SerializeToString())

    signed_signer_device_certificate_signature = wv_proto2_pb2.SignedDeviceCertificate()
    signed_signer_device_certificate_signature._DeviceCertificate.CopyFrom(
        signer_device_certificate)
    signed_signer_device_certificate_signature.Signature = signer_device_certificate_signature.digest()

    signed_device_certificate = wv_proto2_pb2.SignedDeviceCertificate()
    signed_device_certificate._DeviceCertificate.CopyFrom(device_certificate)
    signed_device_certificate.Signature = device_certificate_signature.digest()
    signed_device_certificate.Signer.CopyFrom(
        signed_signer_device_certificate_signature)

    client_id = wv_proto2_pb2.ClientIdentification()
    client_id.Type = 1
    client_id.Token.CopyFrom(signed_device_certificate)

    company_name = wv_proto2_pb2.ClientIdentification.NameValue()
    company_name.Name = "company_name"
    company_name.Value = get_random_company_name()

    # print(f"Company name: {company_name.Value}")

    model_name = wv_proto2_pb2.ClientIdentification.NameValue()
    model_name.Name = "model_name"
    model_name.Value = get_random_string_in_range(
        random.randrange(4, 8)).encode()

    # print(f"Model name: {model_name.Value}")

    architecture_name = wv_proto2_pb2.ClientIdentification.NameValue()
    architecture_name.Name = "architecture_name"
    architecture_name.Value = get_random_arch()

    # print(f"Architecture name: {architecture_name.Value}")

    device_name = wv_proto2_pb2.ClientIdentification.NameValue()
    device_name.Name = "device_name"
    device_name.Value = model_name.Value

    product_name = wv_proto2_pb2.ClientIdentification.NameValue()
    product_name.Name = "product_name"
    product_name.Value = model_name.Value

    os_version = wv_proto2_pb2.ClientIdentification.NameValue()
    os_version.Name = "os_version"
    os_version.Value = ".".join(str(random_number(3)))

    # print(f"OS version: {os_version.Value}")

    build_info = wv_proto2_pb2.ClientIdentification.NameValue()
    build_info.Name = "build_info"
    build_info.Value = generate_build_info(
        company_name.Value, model_name.Value, os_version.Value)

    # print(f"Build info: {build_info.Value}")

    device_id = wv_proto2_pb2.ClientIdentification.NameValue()
    device_id.Name = "device_id"
    device_id.Value = f"{company_name.Value.upper()}_{model_name.Value.upper()}_{get_random_string(4)}_{get_random_string(8)}".rjust(
        32, "0")

    client_id.ClientInfo.append(company_name)
    client_id.ClientInfo.append(model_name)
    client_id.ClientInfo.append(architecture_name)
    client_id.ClientInfo.append(device_name)
    client_id.ClientInfo.append(product_name)
    client_id.ClientInfo.append(os_version)
    client_id.ClientInfo.append(build_info)
    client_id.ClientInfo.append(device_id)

    client_capabilities = wv_proto2_pb2.ClientIdentification.ClientCapabilities()
    client_capabilities.SessionToken = 1
    client_capabilities.MaxHdcpVersion = random.randint(0, 4)
    client_capabilities.OemCryptoApiVersion = random.randint(1, 20)

    client_id._ClientCapabilities.CopyFrom(client_capabilities)

    dir = Path(os.getcwd(), "generated", str(device_certificate.SystemId))
    if dir.exists():
        print(f"SYSTEM ID CLASH: {device_certificate.SystemId}")
        return
    client_id_path = Path(dir, "device_client_id_blob")
    private_key_path = Path(dir, "device_private_key")

    dir.mkdir(parents=True, exist_ok=True)

    open(client_id_path, "wb").write(client_id.SerializeToString())

    # print("Generating Private Key...")
    key = RSA.generate(2048)
    private_key = key.export_key()
    open(private_key_path, "wb").write(private_key)


if __name__ == "__main__":
    to_gen = input("How many CDMs to generate? ")
    for i in range(int(to_gen)):
        print(f"Generating {i + 1}/{to_gen}")
        generate()
