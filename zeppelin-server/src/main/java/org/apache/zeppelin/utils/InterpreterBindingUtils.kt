/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.zeppelin.utils

import java.util.LinkedList

import org.apache.zeppelin.interpreter.InterpreterSetting
import org.apache.zeppelin.notebook.Notebook
import org.apache.zeppelin.types.InterpreterSettingsList

/**
 * Utils for interpreter bindings.
 */
object InterpreterBindingUtils {
    fun getInterpreterBindings(notebook: Notebook,
                               noteId: String): List<InterpreterSettingsList> {
        val settingList = LinkedList<InterpreterSettingsList>()
        val selectedSettings = notebook.getBindedInterpreterSettings(noteId)
        for (setting in selectedSettings) {
            settingList.add(InterpreterSettingsList(setting.id, setting.name,
                    setting.interpreterInfos, true))
        }

        val availableSettings = notebook.interpreterSettingManager.get()
        for (setting in availableSettings) {
            var selected = false
            for (selectedSetting in selectedSettings) {
                if (selectedSetting.id == setting.id) {
                    selected = true
                    break
                }
            }

            if (!selected) {
                settingList.add(InterpreterSettingsList(setting.id, setting.name,
                        setting.interpreterInfos, false))
            }
        }

        return settingList
    }
}
