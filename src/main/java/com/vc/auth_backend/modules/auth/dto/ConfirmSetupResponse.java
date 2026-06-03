package com.vc.auth_backend.modules.auth.dto;

import java.util.List;

public record ConfirmSetupResponse(List<String> backupCodes) {
}
