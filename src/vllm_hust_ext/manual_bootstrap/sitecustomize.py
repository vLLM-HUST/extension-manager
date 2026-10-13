"""Install the Manager-owned vLLM loader patch in spawned Python processes."""

from vllm_hust_ext.runtime_activation import install_manual_activation_from_environment

install_manual_activation_from_environment()
