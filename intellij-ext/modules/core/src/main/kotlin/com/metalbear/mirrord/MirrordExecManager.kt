package com.metalbear.mirrord

import com.intellij.execution.wsl.WSLDistribution
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.project.Project
import com.intellij.util.io.exists

/**
 * Functions to be called when one of our entry points to the program
 * is called - when process is launched, when go entrypoint, etc
 * It will check to see if it already occured for current run
 * and if it did, it will do nothing
 */
object MirrordExecManager {
    var enabled: Boolean = false

    private fun chooseTarget(wslDistribution: WSLDistribution?, project: Project): String? {
        val pods = MirrordApi.listPods(MirrordConfigAPI.getNamespace(project), project, wslDistribution)
        return MirrordExecDialog.selectTargetDialog(pods)
    }

    private fun getConfigPath(project: Project): String? {
        val configPath = MirrordConfigAPI.getConfigPath(project)
        return if (configPath.exists()) {
            configPath.toAbsolutePath().toString()
        } else {
            null
        }
    }
    /**
     * Starts mirrord, shows dialog for selecting pod if target not set
     * and returns env to set.
     */
    fun start(wslDistribution: WSLDistribution?, project: Project): Map<String, String>? {
        if (!enabled) {
            return null
        }
        var target: String? = null;
        if (!MirrordConfigAPI.isTargetSet(project)) {
            ApplicationManager.getApplication().invokeAndWait {
                target = chooseTarget(wslDistribution, project);
            }
        }

        return MirrordApi.exec(target, getConfigPath(project), project, wslDistribution)
    }
}