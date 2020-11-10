package io.humourmind.credhub;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import org.springframework.credhub.core.CredHubOperations;
import org.springframework.credhub.core.credential.CredHubCredentialOperations;
import org.springframework.credhub.core.permissionV2.CredHubPermissionV2Operations;
import org.springframework.credhub.support.CredentialDetails;
import org.springframework.credhub.support.CredentialName;
import org.springframework.credhub.support.SimpleCredentialName;
import org.springframework.credhub.support.json.JsonCredential;
import org.springframework.credhub.support.json.JsonCredentialRequest;
import org.springframework.credhub.support.permissions.Operation;
import org.springframework.credhub.support.permissions.Permission;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BinaryController {

	private static final String APP_GUID = UUID.randomUUID().toString();
	private static final String KEY = "auth";
	private final CredHubCredentialOperations credentialOperations;
	private final CredHubPermissionV2Operations permissionOperations;

	BinaryController(CredHubOperations credentialOperations) {
		this.credentialOperations = credentialOperations.credentials();
		this.permissionOperations = credentialOperations.permissionsV2();
	}

	@GetMapping({ "/v1/persist" })
	public Results persist() throws IOException {
		SimpleCredentialName credentialName = new SimpleCredentialName("kerberos",
				"keytab");
		Results results = new Results();
		String encoded = Base64.getEncoder()
				.encodeToString(IOUtils.toByteArray(Objects.requireNonNull(
						this.getClass().getClassLoader().getResourceAsStream("keytab"))));
		Map<String, Object> value = new HashMap() {
			{
				put(KEY, encoded);
			}
		};
		writeCredentials(credentialName, value, results);
		addCredentialPermissions(credentialName, results);
		return results;
	}

	@GetMapping({ "/v1/retrieve" })
	public Results retrieve() {
		Results results = new Results();
		SimpleCredentialName credentialName = new SimpleCredentialName("kerberos",
				"keytab");
		getCredentialsByName(credentialName, results);
		return results;
	}

	private void writeCredentials(SimpleCredentialName name, Map<String, Object> value,
			Results results) {
		try {
			JsonCredentialRequest request = JsonCredentialRequest.builder().name(name)
					.value(value).build();
			CredentialDetails<JsonCredential> credentialDetails = this.credentialOperations
					.write(request);
			this.saveResults(results, "Successfully wrote credentials: ",
					credentialDetails);
		}
		catch (Exception ex) {
			this.saveResults(results, "Error writing credentials: ", ex.getMessage());
		}
	}

	private void addCredentialPermissions(CredentialName name, Results results) {
		try {
			// set app permission
			Permission permission = Permission.builder().app(APP_GUID)
					.operations(new Operation[] { Operation.READ }).build();
			this.permissionOperations.addPermissions(name, permission);
			this.saveResults(results, "Successfully added permissions");
		}
		catch (Exception ex) {
			this.saveResults(results, "Error adding permission: ", ex.getMessage());
		}

	}

	private void getCredentialsByName(CredentialName name, Results results) {
		try {
			CredentialDetails<JsonCredential> retrievedDetails = this.credentialOperations
					.getByName(name, JsonCredential.class);
			String target = (String) retrievedDetails.getValue().get(KEY);
			FileUtils.writeByteArrayToFile(new File("/tmp/keytab"),
					Base64.getDecoder().decode(target), false);
			this.saveResults(results, "Successfully retrieved credentials by name: ",
					retrievedDetails);
		}
		catch (Exception ex) {
			this.saveResults(results, "Error retrieving credentials by name: ",
					ex.getMessage());
		}

	}

	private void saveResults(Results results, String message) {
		this.saveResults(results, message, "");
	}

	private void saveResults(BinaryController.Results results, String message,
			Object details) {
		results.add(Collections.singletonMap(message, details));
	}

	private static class Results extends ArrayList<Map<String, Object>> {
		private Results() {
		}
	}

}
