import json
from ip_reputation.models import ErrorResponse, StepStatus
from ip_reputation.constants import StatusMessage


def build_error_response(error: Exception, status_code) -> dict:
    response = ErrorResponse(
        step_status=StepStatus(
            code=status_code.value,
            message=StatusMessage.FAILED.value,
        ),
        error=str(error),
    )
    return response.model_dump()


def handle_error(error: Exception, status_code) -> None:
    response = build_error_response(error, status_code)
    print(json.dumps(response, indent=2))
