from __future__ import annotations

import http.cookiejar
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

import server


class OpcaApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir = tempfile.TemporaryDirectory()
        server.DB_PATH = Path(cls.temp_dir.name) / "test.sqlite3"
        server.PRIVATE_UPLOAD_DIR = Path(cls.temp_dir.name) / "pending"
        server.PUBLIC_CARD_DIR = Path(cls.temp_dir.name) / "cards"
        server.initialize_database()
        cls.httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.OpcaHandler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.httpd.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=3)
        cls.temp_dir.cleanup()

    def setUp(self) -> None:
        with server.database() as connection:
            connection.execute("DELETE FROM card_images")
            connection.execute("DELETE FROM photo_submissions")
            connection.execute("DELETE FROM messages")
            connection.execute("DELETE FROM favorites")
            connection.execute("DELETE FROM listings")
            connection.execute("DELETE FROM sessions")
            connection.execute("DELETE FROM users")
        self.seller = self.new_client()
        self.buyer = self.new_client()
        self.outsider = self.new_client()
        self.seller_user = self.register(self.seller, "seller01")
        self.buyer_user = self.register(self.buyer, "buyer001")
        self.outsider_user = self.register(self.outsider, "outside1")

    @staticmethod
    def new_client() -> urllib.request.OpenerDirector:
        jar = http.cookiejar.CookieJar()
        return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    def call(self, client, path: str, method: str = "GET", body: dict | None = None):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        try:
            with client.open(request, timeout=5) as response:
                content = response.read().decode("utf-8")
                return response.status, json.loads(content) if content.startswith("{") else {}
        except urllib.error.HTTPError as error:
            try:
                content = error.read().decode("utf-8")
                return error.code, json.loads(content) if content.startswith("{") else {}
            finally:
                error.close()

    def register(self, client, username: str) -> dict:
        status, response = self.call(client, "/api/auth/register", "POST", {"username": username, "password": "correct-horse-42"})
        self.assertEqual(status, 201, response)
        return response["user"]

    def test_account_nickname_is_generated_and_persistent(self) -> None:
        self.assertEqual(self.seller_user["nickname"], "데굴데굴 준킹볼 105")
        status, session = self.call(self.seller, "/api/session")
        self.assertEqual(status, 200)
        self.assertEqual(session["user"]["nickname"], self.seller_user["nickname"])
        status, _ = self.call(self.seller, "/api/auth/logout", "POST", {})
        self.assertEqual(status, 200)
        status, session = self.call(self.seller, "/api/session")
        self.assertIsNone(session["user"])
        status, _ = self.call(self.seller, "/api/auth/login", "POST", {"username": "seller01", "password": "correct-horse-42"})
        self.assertEqual(status, 200)
        self.assertEqual(self.call(self.seller, "/api/session")[1]["user"]["id"], self.seller_user["id"])

    def test_password_validation_and_duplicate_ids(self) -> None:
        status, _ = self.call(self.new_client(), "/api/auth/register", "POST", {"username": "short", "password": "123"})
        self.assertEqual(status, 400)
        status, _ = self.call(self.new_client(), "/api/auth/register", "POST", {"username": "seller01", "password": "correct-horse-42"})
        self.assertEqual(status, 409)
        status, _ = self.call(self.new_client(), "/api/auth/login", "POST", {"username": "seller01", "password": "incorrect-password"})
        self.assertEqual(status, 401)

    def test_korean_usernames_can_register_and_log_in(self) -> None:
        client = self.new_client()
        status, response = self.call(client, "/api/auth/register", "POST", {"username": "냠냠쩝쩝", "password": "correct-horse-42"})
        self.assertEqual(status, 201, response)
        self.assertEqual(response["user"]["username"], "냠냠쩝쩝")
        status, _ = self.call(client, "/api/auth/logout", "POST", {})
        self.assertEqual(status, 200)
        status, response = self.call(client, "/api/auth/login", "POST", {"username": "냠냠쩝쩝", "password": "correct-horse-42"})
        self.assertEqual(status, 200)
        self.assertEqual(response["user"]["username"], "냠냠쩝쩝")

    def test_listing_favorites_and_private_chat(self) -> None:
        status, created = self.call(self.seller, "/api/listings", "POST", {
            "kind": "판매",
            "payload": {"title": "2026 stage1 JUNBIN", "player": "JUNBIN", "season": "2026", "stage": "stage1", "team": "크레이지 라쿤", "price": 25000},
        })
        self.assertEqual(status, 201)
        listing = created["item"]
        listing_id = listing["id"]
        self.assertEqual(listing["seller"], self.seller_user["nickname"])

        status, items = self.call(self.buyer, "/api/listings")
        self.assertEqual(status, 200)
        self.assertEqual(items["items"][0]["id"], listing_id)

        status, response = self.call(self.buyer, "/api/favorites/toggle", "POST", {"listingId": listing_id})
        self.assertEqual(status, 200)
        self.assertTrue(response["saved"])
        self.assertEqual(self.call(self.buyer, "/api/favorites")[1]["ids"], [listing_id])
        self.assertEqual(self.call(self.seller, "/api/favorites")[1]["ids"], [])

        status, empty_thread = self.call(self.buyer, f"/api/chats/{listing_id}/messages")
        self.assertEqual(status, 200)
        self.assertEqual(empty_thread["items"], [])
        status, sent = self.call(self.buyer, f"/api/chats/{listing_id}/messages", "POST", {"body": "안녕하세요, 아직 거래 가능한가요?"})
        self.assertEqual(status, 201)
        message_id = sent["item"]["id"]
        buyer_chats = self.call(self.buyer, "/api/chats")[1]["items"]
        seller_chats = self.call(self.seller, "/api/chats")[1]["items"]
        self.assertEqual(buyer_chats[0]["listingId"], listing_id)
        self.assertEqual(seller_chats[0]["listingId"], listing_id)
        self.assertEqual(buyer_chats[0]["lastMessage"], "안녕하세요, 아직 거래 가능한가요?")

        status, messages = self.call(self.seller, f"/api/chats/{listing_id}/messages")
        self.assertEqual(status, 200)
        self.assertEqual(messages["items"][0]["id"], message_id)
        status, _ = self.call(self.seller, f"/api/chats/{listing_id}/messages", "POST", {"body": "네, 가능합니다.", "recipientId": self.buyer_user["id"]})
        self.assertEqual(status, 201)

        status, outsider_messages = self.call(self.outsider, f"/api/chats/{listing_id}/messages")
        self.assertEqual(status, 200)
        self.assertEqual(outsider_messages["items"], [])
        status, _ = self.call(self.seller, f"/api/chats/{listing_id}/messages", "POST", {"body": "임의 계정 메시지", "recipientId": self.outsider_user["id"]})
        self.assertEqual(status, 403)

    def test_settings_are_account_scoped(self) -> None:
        status, _ = self.call(self.buyer, "/api/settings", "PATCH", {"chatNotifications": False, "favoriteNotifications": True})
        self.assertEqual(status, 200)
        self.assertEqual(self.call(self.buyer, "/api/settings")[1], {"chatNotifications": False, "favoriteNotifications": True})
        self.assertEqual(self.call(self.seller, "/api/settings")[1], {"chatNotifications": True, "favoriteNotifications": False})

    def test_backup_lists_are_private_and_server_files_are_not_static(self) -> None:
        self.call(self.seller, "/api/listings", "POST", {
            "kind": "판매",
            "payload": {"title": "내 카드", "player": "JUNBIN", "season": "2026", "stage": "stage1", "team": "크레이지 라쿤"},
        })
        self.assertEqual(len(self.call(self.seller, "/api/my/listings")[1]["items"]), 1)
        self.assertEqual(self.call(self.buyer, "/api/my/listings")[1]["items"], [])
        status, _ = self.call(self.seller, "/server.py")
        self.assertEqual(status, 404)
        request = urllib.request.Request(f"{self.base_url}/server.py", method="HEAD")
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.seller.open(request, timeout=5)
        self.assertEqual(error.exception.code, 404)
        error.exception.close()

    def test_default_admin_account_is_jjicjjic(self) -> None:
        original_admin = server.ADMIN_USERNAME
        server.ADMIN_USERNAME = "찍찍이"
        try:
            admin = self.new_client()
            user = self.register(admin, "찍찍이")
            self.assertTrue(user["isAdmin"])
            self.assertEqual(self.call(admin, "/api/admin/photo-submissions")[0], 200)
            self.assertFalse(self.seller_user["isAdmin"])
        finally:
            server.ADMIN_USERNAME = original_admin

    def test_photo_submission_stays_private_until_admin_approval(self) -> None:
        original_admin = server.ADMIN_USERNAME
        server.ADMIN_USERNAME = "moderator"
        admin = self.new_client()
        try:
            admin_user = self.register(admin, "moderator")
            self.assertTrue(admin_user["isAdmin"])
            metadata = {"year": "2026", "stage": "stage3", "team": "크레이지 라쿤", "player": "JUNBIN", "cardType": "정규 시즌", "title": ""}
            image_data = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/r7cAAAAASUVORK5CYII="
            status, response = self.call(self.seller, "/api/photo-submissions", "POST", {"metadata": metadata, "imageData": image_data})
            self.assertEqual(status, 201, response)
            submission_id = response["item"]["id"]
            self.assertEqual(response["item"]["status"], "pending")
            self.assertEqual(self.call(self.seller, "/api/card-images")[1]["items"], [])
            self.assertEqual(self.call(self.buyer, "/api/admin/photo-submissions")[0], 403)

            status, queue = self.call(admin, "/api/admin/photo-submissions")
            self.assertEqual(status, 200)
            self.assertEqual(queue["items"][0]["submitter"], self.seller_user["nickname"])
            image_url = f"{self.base_url}{queue['items'][0]['imageUrl']}"
            buyer_image_request = urllib.request.Request(image_url)
            with self.assertRaises(urllib.error.HTTPError) as forbidden_image:
                self.buyer.open(buyer_image_request, timeout=5)
            self.assertEqual(forbidden_image.exception.code, 403)
            forbidden_image.exception.close()
            admin_image_request = urllib.request.Request(image_url)
            with admin.open(admin_image_request, timeout=5) as image_response:
                self.assertEqual(image_response.headers.get_content_type(), "image/png")
                self.assertTrue(image_response.read().startswith(b"\x89PNG\r\n\x1a\n"))

            status, review = self.call(admin, f"/api/admin/photo-submissions/{submission_id}/review", "POST", {"decision": "approve", "note": "확인 완료"})
            self.assertEqual(status, 200)
            catalog = self.call(self.buyer, "/api/card-images")[1]["items"]
            self.assertEqual(len(catalog), 1)
            self.assertEqual(catalog[0]["player"], "JUNBIN")
            # A later approval for the same card replaces the canonical image entry.
            status, replacement = self.call(self.buyer, "/api/photo-submissions", "POST", {"metadata": metadata, "imageData": image_data})
            self.assertEqual(status, 201)
            replacement_id = replacement["item"]["id"]
            status, replacement_review = self.call(admin, f"/api/admin/photo-submissions/{replacement_id}/review", "POST", {"decision": "approve"})
            self.assertEqual(status, 200)
            replacement_catalog = self.call(self.buyer, "/api/card-images")[1]["items"]
            self.assertEqual(len(replacement_catalog), 1)
            self.assertEqual(replacement_catalog[0]["url"], replacement_review["imageUrl"])
            with self.buyer.open(f"{self.base_url}{review['imageUrl']}", timeout=5) as published_image:
                self.assertEqual(published_image.headers.get_content_type(), "image/png")
                self.assertTrue(published_image.read().startswith(b"\x89PNG\r\n\x1a\n"))
            self.assertEqual(self.call(self.seller, "/api/photo-submissions")[1]["items"][0]["status"], "approved")

            rejected_metadata = {**metadata, "player": "MAX"}
            status, rejected_submission = self.call(self.buyer, "/api/photo-submissions", "POST", {"metadata": rejected_metadata, "imageData": image_data})
            self.assertEqual(status, 201)
            rejected_id = rejected_submission["item"]["id"]
            status, _ = self.call(admin, f"/api/admin/photo-submissions/{rejected_id}/review", "POST", {"decision": "reject"})
            self.assertEqual(status, 200)
            rejected_path = server.PRIVATE_UPLOAD_DIR / f"{rejected_id}.png"
            self.assertFalse(rejected_path.exists())
            self.assertEqual(self.call(self.buyer, "/api/photo-submissions")[1]["items"][0]["status"], "rejected")
        finally:
            server.ADMIN_USERNAME = original_admin


if __name__ == "__main__":
    unittest.main()
