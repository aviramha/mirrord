package com.metalbear.mirrord

import com.goide.execution.GoRunConfigurationBase
import com.goide.execution.GoRunningState
import com.goide.execution.GoRunningState.CommandLineType
import com.goide.execution.extension.GoRunConfigurationExtension
import com.intellij.execution.ExecutionException
import com.intellij.execution.configurations.RunnerSettings
import com.intellij.execution.target.TargetedCommandLineBuilder

class GolandRunConfigurationExtension : GoRunConfigurationExtension() {
    @Throws(ExecutionException::class)
    override fun patchCommandLine(
        configuration: GoRunConfigurationBase<*>,
        runnerSettings: RunnerSettings?,
        cmdLine: TargetedCommandLineBuilder,
        runnerId: String,
        state: GoRunningState<out GoRunConfigurationBase<*>?>,
        commandLineType: CommandLineType
    ) {
        super.patchCommandLine(configuration, runnerSettings, cmdLine, runnerId, state, commandLineType)
    }

    override fun isApplicableFor(configuration: GoRunConfigurationBase<*>): Boolean {
        return true
    }

    override fun isEnabledFor(
        applicableConfiguration: GoRunConfigurationBase<*>,
        runnerSettings: RunnerSettings?
    ): Boolean {
        return true
    }
}