# Form implementation generated from reading ui file 'rsu_testing_app.ui'
#
# Created by: PyQt6 UI code generator 6.5.2
#
# WARNING: Any manual changes made to this file will be lost when pyuic6 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt6 import QtCore, QtGui, QtWidgets


class Ui_CV2X_Automated_Tester(object):
    def setupUi(self, CV2X_Automated_Tester):
        CV2X_Automated_Tester.setObjectName("CV2X_Automated_Tester")
        CV2X_Automated_Tester.resize(830, 712)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("favicon.png"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
        CV2X_Automated_Tester.setWindowIcon(icon)
        self.centralwidget = QtWidgets.QWidget(parent=CV2X_Automated_Tester)
        self.centralwidget.setObjectName("centralwidget")
        self.tabWidget = QtWidgets.QTabWidget(parent=self.centralwidget)
        self.tabWidget.setGeometry(QtCore.QRect(0, 10, 801, 531))
        self.tabWidget.setObjectName("tabWidget")
        self.tab = QtWidgets.QWidget()
        self.tab.setObjectName("tab")
        self.rsuCount_spinBox = QtWidgets.QSpinBox(parent=self.tab)
        self.rsuCount_spinBox.setGeometry(QtCore.QRect(360, 10, 91, 30))
        self.rsuCount_spinBox.setMaximum(5)
        self.rsuCount_spinBox.setObjectName("rsuCount_spinBox")
        self.label = QtWidgets.QLabel(parent=self.tab)
        self.label.setGeometry(QtCore.QRect(10, 10, 351, 31))
        self.label.setObjectName("label")
        self.rsu_frame = QtWidgets.QFrame(parent=self.tab)
        self.rsu_frame.setGeometry(QtCore.QRect(10, 40, 781, 441))
        self.rsu_frame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.rsu_frame.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.rsu_frame.setObjectName("rsu_frame")
        self.label_2 = QtWidgets.QLabel(parent=self.rsu_frame)
        self.label_2.setGeometry(QtCore.QRect(20, 10, 101, 21))
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(parent=self.rsu_frame)
        self.label_3.setGeometry(QtCore.QRect(150, 10, 101, 21))
        self.label_3.setObjectName("label_3")
        self.line = QtWidgets.QFrame(parent=self.rsu_frame)
        self.line.setGeometry(QtCore.QRect(280, 10, 20, 301))
        self.line.setFrameShape(QtWidgets.QFrame.Shape.VLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        self.line.setObjectName("line")
        self.label_4 = QtWidgets.QLabel(parent=self.rsu_frame)
        self.label_4.setGeometry(QtCore.QRect(310, 10, 101, 21))
        self.label_4.setObjectName("label_4")
        self.line_2 = QtWidgets.QFrame(parent=self.rsu_frame)
        self.line_2.setGeometry(QtCore.QRect(370, 10, 20, 301))
        self.line_2.setFrameShape(QtWidgets.QFrame.Shape.VLine)
        self.line_2.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        self.line_2.setObjectName("line_2")
        self.label_5 = QtWidgets.QLabel(parent=self.rsu_frame)
        self.label_5.setGeometry(QtCore.QRect(400, 10, 101, 21))
        self.label_5.setObjectName("label_5")
        self.tabWidget.addTab(self.tab, "")
        self.tab_2 = QtWidgets.QWidget()
        self.tab_2.setObjectName("tab_2")
        self.fuzzer_tabWidget = QtWidgets.QTabWidget(parent=self.tab_2)
        self.fuzzer_tabWidget.setGeometry(QtCore.QRect(10, 10, 781, 471))
        self.fuzzer_tabWidget.setObjectName("fuzzer_tabWidget")
        self.tabWidget.addTab(self.tab_2, "")
        self.tab_3 = QtWidgets.QWidget()
        self.tab_3.setObjectName("tab_3")
        self.snmp_tabWidget = QtWidgets.QTabWidget(parent=self.tab_3)
        self.snmp_tabWidget.setGeometry(QtCore.QRect(10, 10, 781, 471))
        self.snmp_tabWidget.setObjectName("snmp_tabWidget")
        self.tabWidget.addTab(self.tab_3, "")
        self.tab_4 = QtWidgets.QWidget()
        self.tab_4.setObjectName("tab_4")
        self.mesh_tabWidget = QtWidgets.QTabWidget(parent=self.tab_4)
        self.mesh_tabWidget.setGeometry(QtCore.QRect(10, 40, 781, 441))
        self.mesh_tabWidget.setObjectName("mesh_tabWidget")
        self.mesh_top_comboBox = QtWidgets.QComboBox(parent=self.tab_4)
        self.mesh_top_comboBox.setGeometry(QtCore.QRect(10, 10, 51, 29))
        self.mesh_top_comboBox.setObjectName("mesh_top_comboBox")
        self.mesh_top_comboBox.addItem("")
        self.mesh_top_comboBox.addItem("")
        self.mesh_top_comboBox.addItem("")
        self.mesh_top_comboBox.addItem("")
        self.mesh_top_comboBox.addItem("")
        self.mesh_top_comboBox.addItem("")
        self.mesh_top_comboBox.addItem("")
        self.label_6 = QtWidgets.QLabel(parent=self.tab_4)
        self.label_6.setGeometry(QtCore.QRect(70, 10, 91, 21))
        self.label_6.setObjectName("label_6")
        self.mesh_test_pushButton = QtWidgets.QPushButton(parent=self.tab_4)
        self.mesh_test_pushButton.setGeometry(QtCore.QRect(655, 10, 131, 31))
        self.mesh_test_pushButton.setObjectName("mesh_test_pushButton")
        self.tabWidget.addTab(self.tab_4, "")
        self.SAVE_pushButton = QtWidgets.QPushButton(parent=self.centralwidget)
        self.SAVE_pushButton.setGeometry(QtCore.QRect(10, 560, 191, 30))
        self.SAVE_pushButton.setObjectName("SAVE_pushButton")
        self.SAVE_checkBox = QtWidgets.QCheckBox(parent=self.centralwidget)
        self.SAVE_checkBox.setGeometry(QtCore.QRect(210, 560, 411, 27))
        self.SAVE_checkBox.setObjectName("SAVE_checkBox")
        self.IMPORT_pushButton = QtWidgets.QPushButton(parent=self.centralwidget)
        self.IMPORT_pushButton.setGeometry(QtCore.QRect(10, 600, 191, 30))
        self.IMPORT_pushButton.setObjectName("IMPORT_pushButton")
        CV2X_Automated_Tester.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(parent=CV2X_Automated_Tester)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 830, 26))
        self.menubar.setObjectName("menubar")
        CV2X_Automated_Tester.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(parent=CV2X_Automated_Tester)
        self.statusbar.setObjectName("statusbar")
        CV2X_Automated_Tester.setStatusBar(self.statusbar)

        self.retranslateUi(CV2X_Automated_Tester)
        self.tabWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(CV2X_Automated_Tester)

    def retranslateUi(self, CV2X_Automated_Tester):
        _translate = QtCore.QCoreApplication.translate
        CV2X_Automated_Tester.setWindowTitle(_translate("CV2X_Automated_Tester", "C-V2X Automated Tester"))
        self.label.setText(_translate("CV2X_Automated_Tester", "Enter Number of RSUs to be Tested (0-5):"))
        self.label_2.setText(_translate("CV2X_Automated_Tester", "RSU Label"))
        self.label_3.setText(_translate("CV2X_Automated_Tester", "IP Address"))
        self.label_4.setText(_translate("CV2X_Automated_Tester", "Valid"))
        self.label_5.setText(_translate("CV2X_Automated_Tester", "Ping Test"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), _translate("CV2X_Automated_Tester", "RSU Settings"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), _translate("CV2X_Automated_Tester", "Fuzzer Testing"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_3), _translate("CV2X_Automated_Tester", "SNMP Testing"))
        self.mesh_top_comboBox.setItemText(0, _translate("CV2X_Automated_Tester", "---"))
        self.mesh_top_comboBox.setItemText(1, _translate("CV2X_Automated_Tester", "A"))
        self.mesh_top_comboBox.setItemText(2, _translate("CV2X_Automated_Tester", "B"))
        self.mesh_top_comboBox.setItemText(3, _translate("CV2X_Automated_Tester", "C"))
        self.mesh_top_comboBox.setItemText(4, _translate("CV2X_Automated_Tester", "D"))
        self.mesh_top_comboBox.setItemText(5, _translate("CV2X_Automated_Tester", "E"))
        self.mesh_top_comboBox.setItemText(6, _translate("CV2X_Automated_Tester", "F"))
        self.label_6.setText(_translate("CV2X_Automated_Tester", "OBU Port"))
        self.mesh_test_pushButton.setText(_translate("CV2X_Automated_Tester", "Test All Mesh"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_4), _translate("CV2X_Automated_Tester", "Mesh Testing"))
        self.SAVE_pushButton.setText(_translate("CV2X_Automated_Tester", "Save Configuration"))
        self.SAVE_checkBox.setText(_translate("CV2X_Automated_Tester", "Include Passwords (Caution: Saved in Plaintext!)"))
        self.IMPORT_pushButton.setText(_translate("CV2X_Automated_Tester", "Import Configuration"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    CV2X_Automated_Tester = QtWidgets.QMainWindow()
    ui = Ui_CV2X_Automated_Tester()
    ui.setupUi(CV2X_Automated_Tester)
    CV2X_Automated_Tester.show()
    sys.exit(app.exec())
