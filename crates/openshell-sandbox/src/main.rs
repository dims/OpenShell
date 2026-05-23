// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `OpenShell` Sandbox - process sandbox and monitor.

fn main() -> miette::Result<()> {
    openshell_sandbox::cli::run()
}
