#include <iostream>
#include <Windows.h>
#include <wincrypt.h>
#include <vector>
#include <algorithm>
#include <iomanip>

using namespace std;

struct st_prov {
	DWORD prov_type;
	LPSTR name;
};


bool try_get_providers(int index, vector<st_prov>& list) {
	DWORD byte_count, tmp;

	if (!CryptEnumProviders(index, nullptr, 0, &tmp, nullptr, &byte_count)) {
		if (GetLastError() == ERROR_NO_MORE_ITEMS)
			cout << "Got the end of a list (1)" << endl;
		else
			throw "Error 1 in try_get_providers";
		return false;
	}

	st_prov prov{};
	prov.name = new char[byte_count];

	if (!CryptEnumProviders(index, nullptr, 0, &(prov.prov_type), (LPWSTR) prov.name,
		&byte_count)) {
		if (GetLastError() == ERROR_NO_MORE_ITEMS)
			cout << "Got the end of a list (2)" << endl;
		else
			throw "Error 2 in try_get_providers";
		return false;
	}

	list.push_back(prov);

	return true;
}

void get_csp_containers(HCRYPTPROV handle, vector<string>& mas) {
	char buff[512];
	DWORD tmp;

	if (!CryptGetProvParam(handle, PP_ENUMCONTAINERS, (BYTE*)&buff, &tmp, CRYPT_FIRST))
		cout << "In reading containers" << endl;

	while (CryptGetProvParam(handle, PP_ENUMCONTAINERS, (BYTE*)&buff, &tmp, CRYPT_NEXT))
		mas.emplace_back(buff);

	if (GetLastError() != ERROR_NO_MORE_ITEMS)
		cout << "In reading containers (Error: ERROR_NO_MORE_ITEMS)" << endl;
}

void get_information_about_csp(const DWORD csp_type_code, LPSTR csp_name, vector<pair<PROV_ENUMALGS_EX, DWORD>>& map,
	const string& keycase_name) {
	HCRYPTPROV handle;
	vector<string> containers;

	wcout << "Begin work with [" << csp_type_code << "] " << (LPCTSTR)(csp_name) << endl;

	if (!CryptAcquireContext(&handle, nullptr, (LPWSTR) csp_name,
		csp_type_code, 0)) {
		if (GetLastError() == NTE_BAD_KEYSET) {
			cout << "Creating " << keycase_name << " keycontainer" << endl;

			CryptReleaseContext(handle, 0);

			if (!CryptAcquireContext(&handle, (LPWSTR)keycase_name.c_str(), (LPWSTR)csp_name, csp_type_code, CRYPT_NEWKEYSET)) {
				if (GetLastError() == NTE_EXISTS) {
					cout << "Key set " << keycase_name << " already exists, trying to open" << endl;
					CryptReleaseContext(handle, 0);

					if (!CryptAcquireContext(&handle,
						(LPWSTR)keycase_name.c_str(),
						(LPWSTR)(csp_name), csp_type_code, 0))
						throw "In get_information_about_csp with existing key container";

				}
				else
					throw "In get csp handle with create key container";
			}
		}
		else
			cout << "In get_information_about_csp with 0 dwFlags" << endl;
	}

	get_csp_containers(handle, containers);

	if (containers.empty()) {
		cout << "NO CREATED CONTAINERS" << endl;
	}
	else {
		cout << endl << "List of key containers:" << endl;
		for (auto& container : containers)
			cout << container << endl;
		cout << "End of a list of key containers" << endl << endl;
	}


	if (find(containers.begin(), containers.end(), keycase_name) != containers.end()) {
		cout << "Keycontainer " << keycase_name << " already exists" << endl;

		CryptReleaseContext(handle, 0);

		if (!CryptAcquireContext(&handle, (LPWSTR)(keycase_name.c_str()),
			reinterpret_cast<LPWSTR> (csp_name), csp_type_code, 0))
			throw "In get_information_about_csp with existing key container";
	}


	PROV_ENUMALGS_EX param;
	DWORD   param2,
		param_size = sizeof(param),
		param2_size = sizeof(param2);

	if (!CryptGetProvParam(handle, PP_ENUMALGS_EX, (BYTE*)&param, &param_size, CRYPT_FIRST))
		cout << "In starting reading algorithms: PP_ENUMALGS_EX" << endl;

	if (!CryptGetProvParam(handle, PP_KEYX_KEYSIZE_INC, (BYTE*)&param2, &param2_size, CRYPT_FIRST))
		cout << "In starting reading algorithms: PP_KEYX_KEYSIZE_INC" << endl;

	map.emplace_back(pair<PROV_ENUMALGS_EX, DWORD>(param, param2));

	while (CryptGetProvParam(handle, PP_ENUMALGS_EX, (BYTE*)&param, &param_size, CRYPT_NEXT) &&
		CryptGetProvParam(handle, PP_KEYX_KEYSIZE_INC, (BYTE*)&param2, &param2_size, 0)) {
		if (param2) {
			map.emplace_back(pair<PROV_ENUMALGS_EX, DWORD>(param, param2));
		}
	}

	if (GetLastError() != ERROR_NO_MORE_ITEMS)
		cout << "In reading algorithms" << endl;

	sort(map.begin(), map.end(),
		[](pair<PROV_ENUMALGS_EX, DWORD> const& a, pair<PROV_ENUMALGS_EX, DWORD> const& b) {
		return GET_ALG_CLASS(a.first.aiAlgid) < GET_ALG_CLASS(b.first.aiAlgid);
	});

	CryptReleaseContext(handle, 0);
}

void print_information_about_csp(const DWORD csp_type, LPSTR csp_name, vector<pair<PROV_ENUMALGS_EX, DWORD>>& mas) {
	cout << "+" << setw(123) << setfill('-') << "" << "+" << endl;
	cout << "|Type: " << setw(26) << setfill(' ') << left << csp_type << "Name: " << setw(85) << csp_name << "|"
		<< endl;
	cout << setfill('-') << "+" << setw(40) << "" << "+" << setw(15) << "" << "+" << setw(17) << "" << "+" << setw(10)
		<< "" << "+" << setw(10) << "" << "+" << setw(10) << "" << "+" << setw(15) << "" << "+" << endl;
	cout << setfill(' ') << setw(41) << "|#Algorithm Name" << setw(16) << "|#Algorithm ID" << setw(18)
		<< "|#Algorithm Class" << setw(11) << "|#def len" << setw(11) << "|#min len" << setw(11) << "|#max len"
		<< setw(16) << "|#keysize inc" << "|"
		<< endl;
	int One_time_flag = 0;
	for (auto& it : mas) {
		if (GetLastError() != ERROR_INVALID_PARAMETER) {
			if (it.first.aiAlgid != 0xcccccccc) {
				wcout << "|" << left << setw(40) << it.first.szLongName;
				cout << "|" << setw(15) << it.first.aiAlgid;
				cout << "|" << setw(17);
				switch (GET_ALG_CLASS(it.first.aiAlgid)) {
				case ALG_CLASS_ALL:
					cout << "ALL";
					break;
				case ALG_CLASS_ANY:
					cout << "ANY";
					break;
				case ALG_CLASS_DATA_ENCRYPT:
					cout << "DATA_ENCRYPT";
					break;
				case ALG_CLASS_HASH:
					cout << "HASH";
					break;
				case ALG_CLASS_KEY_EXCHANGE:
					cout << "KEY_EXCHANGE";
					break;
				case ALG_CLASS_MSG_ENCRYPT:
					cout << "MSG_ENCRYPT";
					break;
				case ALG_CLASS_SIGNATURE:
					cout << "SIGNATURE";
					break;
				}
				cout << "|" << setw(10) << it.first.dwDefaultLen;
				cout << "|" << setw(10) << it.first.dwMinLen;
				cout << "|" << setw(10) << it.first.dwMaxLen;
				if (GET_ALG_CLASS(it.first.aiAlgid) == ALG_CLASS_DATA_ENCRYPT || GET_ALG_CLASS(it.first.aiAlgid) == ALG_CLASS_SIGNATURE)
					cout << "|" << setw(15) << it.second << setw(10) << "|" << endl;
				else
					cout << "|" << setw(15) << "No info" << setw(10) << "|" << endl;
			}
		}
		else {
			if (One_time_flag == 0)
				cout << "|" << setw(123) << setfill(' ') << left
				<< "No information! (Maybe there is no hardware supporting)" << "|" << endl;
			One_time_flag++;
		}
	}
	cout << setfill('-') << "+" << setw(40) << "" << "+" << setw(15) << "" << "+" << setw(17) << "" << "+" << setw(10)
		<< "" << "+" << setw(10) << "" << "+" << setw(10) << "" << "+" << setw(15) << "" << "+" << endl;
}

void get_csp_handler(DWORD csp_type, LPTSTR csp_name, LPCTSTR container_name, HCRYPTPROV& handler) {

	if (!CryptAcquireContext(&handler, container_name, csp_name, csp_type, 0)) {
		if (GetLastError() == NTE_BAD_KEYSET) {
			wcout << "Creating " << container_name << " key container" << endl;
			CryptReleaseContext(handler, 0);

			if (!CryptAcquireContext(&handler, container_name, csp_name, csp_type, CRYPT_NEWKEYSET)) {

				if (GetLastError() == NTE_EXISTS) {
					CryptReleaseContext(handler, 0);


					if (!CryptAcquireContext(&handler, container_name, csp_name, csp_type, 0))
						throw "In get_csp_handler with existing key container";

				}
				else {
					throw "In get_csp_handler with creating key container";
				}

			}

		}
		else {
			throw "In get_csp_handler with zero dwFlags (0)";
		}
	}
	else {
		wcout << "A cryptographic context with the " << container_name << " key container has been acquired." << endl;
	}

}

int main() {
	try {
		HCRYPTPROV hCryptProv;
		DWORD csp_type = PROV_RSA_FULL;
		auto csp_name = (LPTSTR)MS_STRONG_PROV;

		string name;
		cout << "Enter name of container, which will be created: ";
		cin >> name;

		LPCTSTR container_name = LPCTSTR (name.c_str()); // The name of the container.
		vector<st_prov> providers;
		vector<pair<PROV_ENUMALGS_EX, DWORD>> map;

		get_csp_handler(csp_type, csp_name, container_name, hCryptProv);

		cout << "Start reading CSPs" << endl;
		for (int i = 0; try_get_providers(i, providers); ++i);
		sort(providers.begin(), providers.end(),
			[](const st_prov& a, const st_prov& b) { return a.prov_type < b.prov_type; });
		cout << "CSPs were read!" << endl;

		for (const st_prov& prov : providers) {
			cout << endl << endl;
			get_information_about_csp(prov.prov_type, prov.name, map, name);
			print_information_about_csp(prov.prov_type, prov.name, map);
		}

		system("PAUSE");
		return 0;
	}
	catch (exception & error) {
		cout << "Error message: " << error.what() << endl;
		cout << "System Error Code: " << GetLastError() << endl;

		system("PAUSE");
	}
}