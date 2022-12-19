package com.metalbear.mirrord


import com.intellij.openapi.fileEditor.FileEditorManager
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFileManager
import com.intellij.util.io.exists
import com.intellij.util.io.write
import com.google.gson.Gson
import com.intellij.util.io.readText
import java.nio.file.Path


data class Target (
    val namespace: String?,
    val path: String?
)

data class ConfigData (
    val target: Target?
)

/**
 * Object for interacting with the mirrord config file.
 */
object MirrordConfigAPI {

    const val defaultConfig = """// See documentation here https://mirrord.dev/docs/overview/configuration
{
    "accept_invalid_certificates": false,
    "feature": {
        "network": {
            "incoming": "mirror",
            "outgoing": true
        },
        "fs": "read",
        "env": true
    }
}
    """

    private fun getConfigPath(project: Project): Path {
        val basePath = project.basePath ?: throw Error("couldn't resolve project path");
        return Path.of(basePath, ".mirrord", "mirrord.json")
    }

    /**
     * Opens the config file in the editor, creating it if didn't exist before
     */
    fun openConfig(project: Project) {
        val configPath = getConfigPath(project);
        if (!configPath.exists()) {
            configPath.write(defaultConfig, createParentDirs = true)
        }
        val file = VirtualFileManager.getInstance().refreshAndFindFileByNioPath(configPath)!!
        FileEditorManager.getInstance(project).openFile(file, true)
    }

    /**
     * Retrieves config file and parses it if available.
     */
    private fun getConfigData(project: Project): ConfigData? {
        val configPath = getConfigPath(project)
        if (!configPath.exists()) {
            return null
        }
        val data = configPath.readText()
        val gson = Gson();
        val configData = gson.fromJson(data, ConfigData::class.java)
        return configData
    }

    /**
     * Gets target set in config file, if any.
     */
    private fun getTarget(project: Project): String? {
        val configData = getConfigData(project)
        return configData?.target?.path
    }

    /**
     * Gets namespace set in config file, if any.
     */
    fun getNamespace(project: Project): String? {
        val configData = getConfigData(project)
        return configData?.target?.namespace
    }


    /**
     * Returns whether target is set in config.
     */
    fun isTargetSet(project: Project): Boolean {
        return getTarget(project) != null
    }
}