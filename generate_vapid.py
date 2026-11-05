"""푸시 알림용 VAPID 키를 한 번만 만들어서 출력합니다.

사용법:  python generate_vapid.py
출력된 두 값을 Render 대시보드 > Environment 에 환경변수로 등록하세요.
(PRIVATE 키는 절대 GitHub 등에 올리지 마세요.)
"""
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


key = ec.generate_private_key(ec.SECP256R1())
private_raw = key.private_numbers().private_value.to_bytes(32, "big")
public_raw = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

print("VAPID_PUBLIC_KEY=" + b64url(public_raw))
print("VAPID_PRIVATE_KEY=" + b64url(private_raw))
