#!/usr/bin/env python3

from ctypes import *
import argparse
import sys

p11 = None


def die(message):
    print(message)
    if p11:
        p11.C_Finalize(0)
    sys.exit(1)


CK_PDS_CONFIG_HW_CRYPTO_DISABLED = 0x80000001
CK_PDS_CONFIG_EXPERIMENTAL_FEATURES_ENABLED = 0x80000002


class Configuration(Structure):
    _fields_ = [
        ("type", c_ulong),
        ("value_ptr", c_void_p),
        ("value_len", c_ulong),
    ]


def load_module(path):
    global p11

    p11 = cdll.LoadLibrary(path)

    # Specify method arguments' ctype equivalent

    p11.C_Initialize.argtypes = [c_void_p]
    p11.C_Initialize.restype = c_ulong

    p11.C_Finalize.argtypes = [c_void_p]
    p11.C_Finalize.restype = c_ulong

    # PDS functions

    p11.API_FW_login.argtypes = [c_int, c_char_p, c_uint]
    p11.API_FW_login.restype = c_int

    p11.C_PDS_SetConfigurationValue.argtypes = [c_char_p, c_ulong,
                                                POINTER(Configuration),
                                                c_ulong]
    p11.C_PDS_SetConfigurationValue.restype = c_ulong


def cast_to_void_p(value):
    return cast(pointer(value), c_void_p)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("-m", "--module",
                        default="/opt/procrypt/km3000/lib/libprocryptoki.so",
                        help="cryptoki module to use")

    parser.add_argument("-p", "--ho-pin",
                        required=True,
                        help="operator PIN")

    parser.add_argument("-P", "--ha-pin",
                        required=True,
                        help="admin PIN")

    parser.add_argument("name",
                        help="configuration item name")

    parser.add_argument("value",
                        help="configuration item value")

    args = parser.parse_args()

    config_types = {
        "hw_crypto_disabled": CK_PDS_CONFIG_HW_CRYPTO_DISABLED,
        "experimental_features_enabled":
            CK_PDS_CONFIG_EXPERIMENTAL_FEATURES_ENABLED,
    }

    if args.name not in config_types:
        names = " ".join(config_types.keys())
        die("Name must be one of these: {}".format(names))

    load_module(args.module)

    rv = p11.C_Initialize(0)
    if rv:
        die("C_Initialize failed. rv={}".format(rv))

    rv = p11.API_FW_login(1, bytes(args.ho_pin, "utf8"), len(args.ho_pin))
    if rv:
        die("API_FW_login failed. rv={}".format(rv))

    value = c_char(1) if eval(args.value) else c_char(0)

    config = Configuration(config_types[args.name], cast_to_void_p(value),
                           c_ulong(sizeof(value)))

    rv = p11.C_PDS_SetConfigurationValue(bytes(args.ha_pin, "utf8"),
                                         len(args.ha_pin), byref(config),
                                         c_ulong(1))
    if rv:
        die("C_PDS_SetConfigurationValue failed. rv={}".format(rv))

    p11.C_Finalize(0)


if __name__ == "__main__":
    main()
