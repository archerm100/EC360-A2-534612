import unittest
from auth_service import register_user, users, verify_password

class TestAuth(unittest.TestCase):

    def setUp(self):
        users.clear()

    def test_successful_registration(self):
        result, status = register_user(
            "alice@example.com", "Password1234"
        )
        self.assertEqual(status, 201)
        self.assertEqual(result, "pending_verification")

    def test_duplicate_registration(self):
        register_user("alice@example.com", "Password1234")
        result, status = register_user(
            "alice@example.com", "Password1234"
        )
        self.assertEqual(status, 409)

    def test_invalid_email(self):
        result, status = register_user(
            "invalid-email", "Password1234"
        )
        self.assertEqual(status, 400)

    def test_short_password(self):
        result, status = register_user(
            "alice@example.com", "123"
        )
        self.assertEqual(status, 400)

    def test_password_hashing(self):
        register_user("alice@example.com", "Password1234")
        stored = users["alice@example.com"]["password"]
        self.assertNotEqual(stored, "Password1234")
        self.assertTrue(verify_password("Password1234", stored))

if __name__ == "__main__":
    unittest.main()
