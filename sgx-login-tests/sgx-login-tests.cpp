#include "pch.h"
#include "CppUnitTest.h"
#include "../sgx-login/sgx-login.h"
#include "sgx-login-enclave_u.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace sgxlogintests
{
	TEST_CLASS(sgxlogintests)
	{
	public:
		
		TEST_METHOD(login_success)
		{
			int token = login();
			bool verified = sgx_verify(token);

			Assert::AreEqual(true, verified);
		}


		TEST_METHOD(sgx_logout_fail_min)
		{
			bool success = sgx_logout(-10);

			Assert::AreEqual(false, success);
		}


		TEST_METHOD(sgx_logout_fail_max)
		{
			bool success = sgx_logout(999);

			Assert::AreEqual(false, success);
		}

		TEST_METHOD(sgx_logout_fail)
		{
			bool success = sgx_logout(3);

			Assert::AreEqual(false, success);
		}

		TEST_METHOD(sgx_logout_success)
		{
			int token = login();
			sgx_logout(token);
			bool verified = sgx_verify(token);

			Assert::AreEqual(false, verified);
		}
	};
}
