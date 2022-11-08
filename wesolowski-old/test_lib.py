import pytest

from scryptlib import (
        compile_contract, build_contract_class, build_type_classes,
        Bytes
        )


contract = 'test.scrypt'

compiler_result = compile_contract(contract, debug=True)
desc = compiler_result.to_desc()

# Load desc instead:
#with open('./out/test_desc.json', 'r') as f:
#    desc = json.load(f)

type_classes = build_type_classes(desc)

VDFVerifierWeslowskiTest = build_contract_class(desc)
vdf_verfifier_weslowski_test = VDFVerifierWeslowskiTest()

@pytest.mark.parametrize(
    "seed, entropy",
    [
        ('abcd', 'aaf2bf8b0d9b3b2460493b50b1b5e55928ff4c30c9fec772c8515ced0364aeda7e570590ca8a51c2cb394edbfe7c725cbc9f9875d0bce873bc3695b95d4297d248059cf7a3e59afac18c74ea71023b26ad3ab61976e2782d2186becd79644a31030d7e6cca60e7dca796d418479bbec1167a76ca9afb933e9a66b04e70b6358a57139a45e108baf3acdef6bc021ce3a3aac077d4a0252270c3e4557acf649742fd45ad9275e5541a23f555b7c2f01dcf1a3939e9a28286e7b9b91d6f6f894f115c6d9564e80e7b49ea7736f1ae8a1c56654cbc44687a63f3218a59f8591b956b06aa7fade07145114a71a784c6bcb5de7243133a32c9a6cd6d966f37b0fabf1c6d78'),
        ('ffabffac', 'febeaf4b1233f793025d51f552b985b22a1b8194f1328d7951dbcd51dcadc3083c95cb72a14d8d895bf22f32f37eb94cff7b6f5cd420106a8804fddee9585fe8fad85aefdca1b534eaadae52d3bbb89298114cee49cf85ba5055ef0dbe7303a43a7e14e8d39219d2a7aa14f58a1aa5fe7f31908d273d8ef0b90250b9ec072a0238d96dd4035a26645e460ddbf5a7af9899a969fa74be7ee486662451508b0bb2bd1aa72e8971ebf45d89ce9418f591bbca5fc9eb978cba94b875579c09c9036f1504d0a0952010fc896b73c790329e4f31a1ddba8f8e6113a807e803eb5c415cb5933e1ea3f051331ed969d6abbafd7b534ceeab5c3ef0e50d5046bdfd75813f4874')
    ]
)
def test_entropy_from_seed(seed, entropy):
    assert vdf_verfifier_weslowski_test.testEntropyFromSeed(
            Bytes(seed),
            Bytes(entropy)
    ).verify()

@pytest.mark.parametrize(
    "seed, discriminant",
    [
        ('abcd', 123),
    ]
)
def test_create_discriminant(seed, discriminant):
    assert vdf_verfifier_weslowski_test.testCreateDiscriminant(
            Bytes(seed),
            discriminant
    ).verify()
