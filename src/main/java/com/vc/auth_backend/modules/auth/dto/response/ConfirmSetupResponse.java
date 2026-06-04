package com.vc.auth_backend.modules.auth.dto.response;

import java.util.List;

public record ConfirmSetupResponse(List<String> backupCodes) {
}
