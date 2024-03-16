from PyQt6 import QtCore, QtWidgets
import os

def fill_fuzzer_tab(self, fuzzer_top_tab: QtWidgets.QTabWidget, row: int):

    # Create frame for all fields
    fuzzer_tab = QtWidgets.QFrame(parent=fuzzer_top_tab)
    fuzzer_tab.setGeometry(QtCore.QRect(10, 30, 781, 471))

    # Create checkbox for enabling fuzzer tests
    fuzzer_enabled_checkBox = QtWidgets.QCheckBox(parent=fuzzer_top_tab)
    fuzzer_enabled_checkBox.setGeometry(QtCore.QRect(10, 10, 401, 21))
    fuzzer_enabled_checkBox.setObjectName("fuzzer_enabled_checkBox")
    fuzzer_enabled_checkBox.setText("Enable fuzzer tests for this RSU")
    fuzzer_enabled_checkBox.setChecked(True)
    fuzzer_enabled_checkBox.stateChanged.connect(lambda: self.update_fuzzer_dict(row, "enabled", fuzzer_enabled_checkBox.isChecked()))
    fuzzer_enabled_checkBox.stateChanged.connect(lambda: fuzzer_tab.setEnabled(fuzzer_enabled_checkBox.isChecked()))

    fuzzer_output_label = QtWidgets.QLabel(parent=fuzzer_tab)
    fuzzer_output_label.setGeometry(QtCore.QRect(420, 10, 80, 21))
    fuzzer_output_label.setObjectName("fuzzer_output_label")
    fuzzer_output_label.setText("Output:")

    fuzzer_output_textEdit = QtWidgets.QTextEdit(parent=fuzzer_tab)
    fuzzer_output_textEdit.setGeometry(QtCore.QRect(420, 30, 321, 371))
    fuzzer_output_textEdit.setObjectName("fuzzer_output_textEdit")
    fuzzer_output_textEdit.setReadOnly(True)

    # Create checkbox to make sure .asn1 files are present
    fuzzer_asn1_checkBox = QtWidgets.QCheckBox(parent=fuzzer_tab)
    fuzzer_asn1_checkBox.setGeometry(QtCore.QRect(10, 50, 401, 71))
    fuzzer_asn1_checkBox.setObjectName("fuzzer_asn1_checkBox")
    fuzzer_asn1_checkBox.setEnabled(True)
    
    # Check the fuzzer box if the asn1 files are present in v2xFuzzyTester/v2xMessageCodec/asncode
    files_present = False

    # Get list of all files in the v2xFuzzyTester/v2xMessageCodec/asncode directory
    cur_dir = os.getcwd()
    
    try:
        files = os.listdir(cur_dir + "/v2xFuzzyTester/v2xMessageCodec/asncode/")
        for file in files:
            if file.endswith(".asn1"):
                files_present = True
                break

    except FileNotFoundError:
        files_present = False

    if files_present:
        # Green text if files are present
        fuzzer_asn1_checkBox.setStyleSheet("color: green")
        fuzzer_asn1_checkBox.setText("ASN1 files present")
        fuzzer_asn1_checkBox.setChecked(True)
    else:
        fuzzer_asn1_checkBox.setStyleSheet("color: red")
        fuzzer_asn1_checkBox.setText("ASN1 files not present.\nPlease acquire them and complie as instructed in the\nsrc/v2xFuzzyTester/v2xMessageCodec/README.md\nfile and restart the application.")
        fuzzer_asn1_checkBox.setChecked(False)



    # Create the run tests button
    fuzzer_run_pushButton = QtWidgets.QPushButton(parent=fuzzer_tab)
    fuzzer_run_pushButton.setGeometry(QtCore.QRect(10, 130, 106, 30))
    fuzzer_run_pushButton.setObjectName("fuzzer_run_pushButton")
    fuzzer_run_pushButton.setText("Run Tests")
    fuzzer_run_pushButton.clicked.connect(lambda: self.run_fuzzer_test(row))
    fuzzer_run_pushButton.setEnabled(fuzzer_asn1_checkBox.isChecked())





    return fuzzer_top_tab



# def fill_ssh_tab(self, ssh_top_tab: QtWidgets.QTabWidget, row: int):
#    
#     # Create frame for all fields
#     ssh_tab = QtWidgets.QFrame(parent=ssh_top_tab)
#     ssh_tab.setGeometry(QtCore.QRect(10, 30, 781, 471))
#
#     # Create checkbox for enabling SSH tests
#     ssh_enabled_checkBox = QtWidgets.QCheckBox(parent=ssh_top_tab)
#     ssh_enabled_checkBox.setGeometry(QtCore.QRect(10, 10, 401, 21))
#     ssh_enabled_checkBox.setObjectName("ssh_enabled_checkBox") 
#     ssh_enabled_checkBox.setText("Enable SSH tests for this RSU")
#     ssh_enabled_checkBox.setChecked(True)
#     ssh_enabled_checkBox.stateChanged.connect(lambda: self.update_ssh_dict(row, "enabled", ssh_enabled_checkBox.isChecked()))
#     ssh_enabled_checkBox.stateChanged.connect(lambda: ssh_tab.setEnabled(ssh_enabled_checkBox.isChecked()))
# 
#     # Create all fields
#    
#     return ssh_top_tab

def fill_snmp_with_snmp(self, snmp_tab: QtWidgets.QTabWidget, row: int):
    # Create all fields
    snmp_ver_label = QtWidgets.QLabel(parent=snmp_tab)
    snmp_ver_label.setGeometry(QtCore.QRect(10, 20, 141, 21))
    snmp_ver_label.setAlignment(QtCore.Qt.AlignmentFlag.AlignRight|QtCore.Qt.AlignmentFlag.AlignTrailing|QtCore.Qt.AlignmentFlag.AlignVCenter)
    snmp_ver_label.setObjectName("snmp_ver_label")
    snmp_ver_label.setText("Version:")
    snmp_snm_label = QtWidgets.QLabel(parent=snmp_tab)
    snmp_snm_label.setGeometry(QtCore.QRect(10, 50, 141, 21))
    snmp_snm_label.setAlignment(QtCore.Qt.AlignmentFlag.AlignRight|QtCore.Qt.AlignmentFlag.AlignTrailing|QtCore.Qt.AlignmentFlag.AlignVCenter)
    snmp_snm_label.setObjectName("snmp_snm_label")
    snmp_snm_label.setText("Security Name:")
    snmp_slv_label = QtWidgets.QLabel(parent=snmp_tab)
    snmp_slv_label.setGeometry(QtCore.QRect(10, 80, 141, 21))
    snmp_slv_label.setAlignment(QtCore.Qt.AlignmentFlag.AlignRight|QtCore.Qt.AlignmentFlag.AlignTrailing|QtCore.Qt.AlignmentFlag.AlignVCenter)
    snmp_slv_label.setObjectName("snmp_slv_label")
    snmp_slv_label.setText("Security Level:")
    snmp_aty_label = QtWidgets.QLabel(parent=snmp_tab)
    snmp_aty_label.setGeometry(QtCore.QRect(10, 110, 141, 21))
    snmp_aty_label.setAlignment(QtCore.Qt.AlignmentFlag.AlignRight|QtCore.Qt.AlignmentFlag.AlignTrailing|QtCore.Qt.AlignmentFlag.AlignVCenter)
    snmp_aty_label.setObjectName("snmp_aty_label")
    snmp_aty_label.setText("Auth Type:")
    snmp_pty_label = QtWidgets.QLabel(parent=snmp_tab)
    snmp_pty_label.setGeometry(QtCore.QRect(10, 170, 141, 21))
    snmp_pty_label.setAlignment(QtCore.Qt.AlignmentFlag.AlignRight|QtCore.Qt.AlignmentFlag.AlignTrailing|QtCore.Qt.AlignmentFlag.AlignVCenter)
    snmp_pty_label.setObjectName("snmp_pty_label")
    snmp_pty_label.setText("Priv Type:")
    snmp_ppa_label = QtWidgets.QLabel(parent=snmp_tab)
    snmp_ppa_label.setGeometry(QtCore.QRect(10, 200, 141, 21))
    snmp_ppa_label.setAlignment(QtCore.Qt.AlignmentFlag.AlignRight|QtCore.Qt.AlignmentFlag.AlignTrailing|QtCore.Qt.AlignmentFlag.AlignVCenter)
    snmp_ppa_label.setObjectName("snmp_ppa_label")
    snmp_ppa_label.setText("Priv Passphrase:")
    snmp_apa_label = QtWidgets.QLabel(parent=snmp_tab)
    snmp_apa_label.setGeometry(QtCore.QRect(10, 140, 141, 21))
    snmp_apa_label.setAlignment(QtCore.Qt.AlignmentFlag.AlignRight|QtCore.Qt.AlignmentFlag.AlignTrailing|QtCore.Qt.AlignmentFlag.AlignVCenter)
    snmp_apa_label.setObjectName("snmp_apa_label")
    snmp_apa_label.setText("Auth Passphrase:")
    snmp_port_label = QtWidgets.QLabel(parent=snmp_tab)
    snmp_port_label.setGeometry(QtCore.QRect(10, 230, 141, 21))
    snmp_port_label.setObjectName("snmp_port_label")
    snmp_port_label.setText("Port:")
    snmp_port_label.setAlignment(QtCore.Qt.AlignmentFlag.AlignRight|QtCore.Qt.AlignmentFlag.AlignTrailing|QtCore.Qt.AlignmentFlag.AlignVCenter)
    snmp_ver_lineEdit = QtWidgets.QLineEdit(parent=snmp_tab)
    snmp_ver_lineEdit.setGeometry(QtCore.QRect(160, 20, 141, 21))
    snmp_ver_lineEdit.setObjectName("snmp_ver_lineEdit")
    # snmp_ver_lineEdit.textChanged.connect(lambda: self.update_snmp_dict(row, "version", snmp_ver_lineEdit.text()))
    snmp_ver_lineEdit.setText("-v3")
    snmp_ver_lineEdit.setReadOnly(True)
    snmp_snm_lineEdit = QtWidgets.QLineEdit(parent=snmp_tab)
    snmp_snm_lineEdit.setGeometry(QtCore.QRect(160, 50, 141, 21))
    snmp_snm_lineEdit.setObjectName("snmp_snm_lineEdit")
    snmp_snm_lineEdit.textChanged.connect(lambda: self.update_snmp_dict(row, "-u", snmp_snm_lineEdit.text()))
    snmp_slv_lineEdit = QtWidgets.QLineEdit(parent=snmp_tab)
    snmp_slv_lineEdit.setGeometry(QtCore.QRect(160, 80, 141, 21))
    snmp_slv_lineEdit.setObjectName("snmp_slv_lineEdit")
    snmp_slv_lineEdit.textChanged.connect(lambda: self.update_snmp_dict(row, "-l", snmp_slv_lineEdit.text()))
    snmp_aty_lineEdit = QtWidgets.QLineEdit(parent=snmp_tab)
    snmp_aty_lineEdit.setGeometry(QtCore.QRect(160, 110, 141, 21))
    snmp_aty_lineEdit.setObjectName("snmp_aty_lineEdit")
    snmp_aty_lineEdit.textChanged.connect(lambda: self.update_snmp_dict(row, "-a", snmp_aty_lineEdit.text()))
    snmp_apa_lineEdit = QtWidgets.QLineEdit(parent=snmp_tab)
    snmp_apa_lineEdit.setGeometry(QtCore.QRect(160, 140, 141, 21))
    snmp_apa_lineEdit.setObjectName("snmp_apa_lineEdit")
    snmp_apa_lineEdit.textChanged.connect(lambda: self.update_snmp_dict(row, "-A", snmp_apa_lineEdit.text()))
    snmp_apa_lineEdit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
    snmp_pty_lineEdit = QtWidgets.QLineEdit(parent=snmp_tab)
    snmp_pty_lineEdit.setGeometry(QtCore.QRect(160, 170, 141, 21))
    snmp_pty_lineEdit.setObjectName("snmp_pty_lineEdit")
    snmp_pty_lineEdit.textChanged.connect(lambda: self.update_snmp_dict(row, "-x", snmp_pty_lineEdit.text()))
    snmp_ppa_lineEdit = QtWidgets.QLineEdit(parent=snmp_tab)
    snmp_ppa_lineEdit.setGeometry(QtCore.QRect(160, 200, 141, 21))
    snmp_ppa_lineEdit.setObjectName("snmp_ppa_lineEdit")
    snmp_ppa_lineEdit.textChanged.connect(lambda: self.update_snmp_dict(row, "-X", snmp_ppa_lineEdit.text()))
    snmp_ppa_lineEdit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
    snmp_port_lineEdit = QtWidgets.QLineEdit(parent=snmp_tab)
    snmp_port_lineEdit.setGeometry(QtCore.QRect(160, 230, 141, 21))
    snmp_port_lineEdit.setObjectName("snmp_port_lineEdit")
    snmp_port_lineEdit.textChanged.connect(lambda: self.update_snmp_dict(row, "-p", snmp_port_lineEdit.text()))
    snmp_port_lineEdit.setText("161")
    snmp_run_pushButton = QtWidgets.QPushButton(parent=snmp_tab)
    snmp_run_pushButton.setGeometry(QtCore.QRect(110, 260, 106, 30))
    snmp_run_pushButton.setObjectName("snmp_run_pushButton")
    snmp_run_pushButton.setText("Run Tests")
    snmp_apa_checkBox = QtWidgets.QCheckBox(parent=snmp_tab)
    snmp_apa_checkBox.setGeometry(QtCore.QRect(310, 140, 71, 21))
    snmp_apa_checkBox.setObjectName("snmp_apa_checkBox")
    snmp_apa_checkBox.setText("Show")
    snmp_apa_checkBox.clicked.connect(
        lambda: snmp_apa_lineEdit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Normal 
        if snmp_apa_checkBox.isChecked() else QtWidgets.QLineEdit.EchoMode.Password)
    )
    snmp_ppa_checkBox = QtWidgets.QCheckBox(parent=snmp_tab)
    snmp_ppa_checkBox.setGeometry(QtCore.QRect(310, 200, 71, 21))
    snmp_ppa_checkBox.setObjectName("snmp_ppa_checkBox")
    snmp_ppa_checkBox.setText("Show")
    snmp_ppa_checkBox.clicked.connect(
        lambda: snmp_ppa_lineEdit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Normal
        if snmp_ppa_checkBox.isChecked() else QtWidgets.QLineEdit.EchoMode.Password)
    )

    return snmp_tab

def fill_snmp_with_ssh(self, snmp_tab: QtWidgets.QTabWidget, row: int):
    ssh_usr_label = QtWidgets.QLabel(parent=snmp_tab)
    ssh_usr_label.setGeometry(QtCore.QRect(10, 20, 80, 21))
    ssh_usr_label.setObjectName("ssh_usr_label")
    ssh_usr_label.setText("Username")
    ssh_usr_lineEdit = QtWidgets.QLineEdit(parent=snmp_tab)
    ssh_usr_lineEdit.setGeometry(QtCore.QRect(10, 50, 141, 29))
    ssh_usr_lineEdit.setObjectName("ssh_usr_lineEdit")
    ssh_usr_lineEdit.textChanged.connect(lambda: self.update_ssh_dict(row, "username", ssh_usr_lineEdit.text()))
    ssh_pwd_label = QtWidgets.QLabel(parent=snmp_tab)
    ssh_pwd_label.setGeometry(QtCore.QRect(10, 90, 101, 21))
    ssh_pwd_label.setObjectName("ssh_pwd_label")
    ssh_pwd_label.setText("Password")
    ssh_pwd_lineEdit = QtWidgets.QLineEdit(parent=snmp_tab)
    ssh_pwd_lineEdit.setGeometry(QtCore.QRect(10, 120, 141, 29))
    ssh_pwd_lineEdit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
    ssh_pwd_lineEdit.setObjectName("ssh_pwd_lineEdit")
    ssh_pwd_lineEdit.textChanged.connect(lambda: self.update_ssh_dict(row, "password", ssh_pwd_lineEdit.text()))
    ssh_pwd_checkBox = QtWidgets.QCheckBox(parent=snmp_tab)
    ssh_pwd_checkBox.setGeometry(QtCore.QRect(170, 120, 110, 27))
    ssh_pwd_checkBox.setObjectName("ssh_pwd_checkBox")
    ssh_pwd_checkBox.setText("Show")
    ssh_pwd_checkBox.stateChanged.connect(
        lambda: ssh_pwd_lineEdit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Normal 
        if ssh_pwd_checkBox.isChecked() else QtWidgets.QLineEdit.EchoMode.Password)
    )
    ssh_run_pushButton = QtWidgets.QPushButton(parent=snmp_tab)
    ssh_run_pushButton.setGeometry(QtCore.QRect(10, 240, 106, 30))
    ssh_run_pushButton.setObjectName("ssh_run_pushButton")
    ssh_run_pushButton.setText("Run Tests")
    ssh_port_label = QtWidgets.QLabel(parent=snmp_tab)
    ssh_port_label.setGeometry(QtCore.QRect(10, 160, 80, 21))
    ssh_port_label.setObjectName("ssh_port_label")
    ssh_port_label.setText("Port")
    ssh_port_lineEdit = QtWidgets.QLineEdit(parent=snmp_tab)
    ssh_port_lineEdit.setGeometry(QtCore.QRect(10, 190, 141, 29))
    ssh_port_lineEdit.setObjectName("ssh_port_lineEdit")
    ssh_port_lineEdit.setText("22")
    ssh_port_lineEdit.textChanged.connect(lambda: self.update_ssh_dict(row, "port", ssh_port_lineEdit.text()))

    return snmp_tab

def update_snmp_tab(self, snmp_top_tab: QtWidgets.QFrame, row: int, use_ssh: bool):
    frame = snmp_top_tab.findChildren(QtWidgets.QFrame)[0]
    stuff = frame.findChildren(QtWidgets.QLineEdit)
    stuff += frame.findChildren(QtWidgets.QCheckBox)
    stuff += frame.findChildren(QtWidgets.QLabel)
    stuff += frame.findChildren(QtWidgets.QPushButton)

    for item in stuff:
        item.deleteLater()


    if not use_ssh:
        frame = fill_snmp_with_snmp(self, frame, row)
    else:
        frame = fill_snmp_with_ssh(self, frame, row)

    return snmp_top_tab
    
    # snmp_tab.setEnabled(self.rsu_list[row].snmp_dict["enabled"])
    # snmp_tab.findChild(QtWidgets.QLineEdit, "snmp_snm_lineEdit").setText(self.rsu_list[row].snmp_dict["-u"])
    # snmp_tab.findChild(QtWidgets.QLineEdit, "snmp_slv_lineEdit").setText(self.rsu_list[row].snmp_dict["-l"])
    # snmp_tab.findChild(QtWidgets.QLineEdit, "snmp_aty_lineEdit").setText(self.rsu_list[row].snmp_dict["-a"])
    # snmp_tab.findChild(QtWidgets.QLineEdit, "snmp_apa_lineEdit").setText(self.rsu_list[row].snmp_dict["-A"])
    # snmp_tab.findChild(QtWidgets.QLineEdit, "snmp_pty_lineEdit").setText(self.rsu_list[row].snmp_dict["-x"])
    # snmp_tab.findChild(QtWidgets.QLineEdit, "snmp_ppa_lineEdit").setText(self.rsu_list[row].snmp_dict["-X"])
    # snmp_tab.findChild(QtWidgets.QLineEdit, "snmp_port_lineEdit").setText(self.rsu_list[row].snmp_dict["-p"])


def fill_snmp_tab(self, snmp_top_tab: QtWidgets.QTabWidget, row: int):

    # Create frame for all fields
    snmp_tab = QtWidgets.QFrame(parent=snmp_top_tab)
    snmp_tab.setGeometry(QtCore.QRect(10, 30, 781, 471)) 
    
    # Create checkbox for enabling SNMP tests
    snmp_enabled_checkBox = QtWidgets.QCheckBox(parent=snmp_top_tab)
    snmp_enabled_checkBox.setGeometry(QtCore.QRect(10, 10, 401, 21))
    snmp_enabled_checkBox.setObjectName("snmp_enabled_checkBox")
    snmp_enabled_checkBox.setText("Enable SNMP tests for this RSU")
    snmp_enabled_checkBox.setChecked(False)
    # snmp_enabled_checkBox.stateChanged.connect(lambda: self.update_snmp_dict(row, "enabled", snmp_enabled_checkBox.isChecked()))
    # snmp_enabled_checkBox.stateChanged.connect(lambda: self.update_ssh_dict(row, "enabled", snmp_enabled_checkBox.isChecked()))
    snmp_enabled_checkBox.stateChanged.connect(lambda: snmp_tab.setEnabled(snmp_enabled_checkBox.isChecked()))

    snmp_or_ssh_tab = QtWidgets.QTabWidget(parent=snmp_tab)
    snmp_or_ssh_tab.setGeometry(QtCore.QRect(10, 10, 381, 331))
    snmp_or_ssh_tab.setObjectName("snmp_or_ssh_tab")

    snmp_snmp_tab = QtWidgets.QTabWidget()
    snmp_snmp_tab = fill_snmp_with_snmp(self, snmp_snmp_tab, row)

    snmp_ssh_tab = QtWidgets.QTabWidget()
    snmp_ssh_tab = fill_snmp_with_ssh(self, snmp_ssh_tab, row)

    snmp_or_ssh_tab.addTab(snmp_snmp_tab, "SNMP")
    snmp_or_ssh_tab.addTab(snmp_ssh_tab, "SSH")

    snmp_or_ssh_tab.currentChanged.connect(lambda: self.update_ssh_dict(row, "enabled", snmp_or_ssh_tab.currentIndex() == 1))
    snmp_or_ssh_tab.currentChanged.connect(lambda: self.update_snmp_dict(row, "enabled", snmp_or_ssh_tab.currentIndex() == 0))

    snmp_output_label = QtWidgets.QLabel(parent=snmp_tab)
    snmp_output_label.setGeometry(QtCore.QRect(420, 10, 80, 21))
    snmp_output_label.setObjectName("snmp_output_label")
    snmp_output_label.setText("Output:")

    snmp_output_textEdit = QtWidgets.QTextEdit(parent=snmp_tab)
    snmp_output_textEdit.setGeometry(QtCore.QRect(420, 30, 321, 371))
    snmp_output_textEdit.setObjectName("snmp_output_textEdit")
    snmp_output_textEdit.setReadOnly(True)

    return snmp_top_tab

def fill_mesh_tab(self, mesh_top_tab: QtWidgets.QTabWidget, row: int):

    # Create mesh tab
    mesh_tab = QtWidgets.QFrame(parent=mesh_top_tab)
    mesh_tab.setGeometry(QtCore.QRect(10, 30, 781, 471))

    # Create checkbox for mesh tab
    mesh_enabled_checkBox = QtWidgets.QCheckBox(parent=mesh_top_tab)
    mesh_enabled_checkBox.setGeometry(QtCore.QRect(10, 10, 401, 21))
    mesh_enabled_checkBox.setObjectName("mesh_enabled_checkBox")
    mesh_enabled_checkBox.setText("Enable Mesh tests for this RSU")
    mesh_enabled_checkBox.setChecked(True)
    mesh_enabled_checkBox.stateChanged.connect(lambda: self.update_mesh_dict(row, "enabled", mesh_enabled_checkBox.isChecked()))
    mesh_enabled_checkBox.stateChanged.connect(lambda: mesh_tab.setEnabled(mesh_enabled_checkBox.isChecked()))

    # Create the fields
    mesh_combo_box = QtWidgets.QComboBox(parent=mesh_tab)
    mesh_combo_box.setGeometry(QtCore.QRect(90, 20, 41, 21))
    mesh_combo_box.setObjectName("mesh_combo_box")
    mesh_combo_box.addItems(["---", "A", "B", "C", "D", "E", "F"])
    mesh_combo_box.currentIndexChanged.connect(lambda: self.update_mesh_dict(row, "port", mesh_combo_box.currentText()))

    mesh_port_label = QtWidgets.QLabel(parent=mesh_tab)
    mesh_port_label.setGeometry(QtCore.QRect(10, 20, 80, 21))
    mesh_port_label.setObjectName("mesh_port_label")
    mesh_port_label.setText("Mesh Port:")

    mesh_static_att_label = QtWidgets.QLabel(parent=mesh_tab)
    mesh_static_att_label.setGeometry(QtCore.QRect(10, 50, 130, 21))
    mesh_static_att_label.setObjectName("mesh_static_att_label")
    mesh_static_att_label.setText("Static Attenuation:")

    mesh_static_att_lineEdit = QtWidgets.QLineEdit(parent=mesh_tab)
    mesh_static_att_lineEdit.setGeometry(QtCore.QRect(150, 50, 61, 21))
    mesh_static_att_lineEdit.setObjectName("mesh_static_att_lineEdit")
    mesh_static_att_lineEdit.setText("95.25")
    mesh_static_att_lineEdit.textChanged.connect(lambda: self.update_mesh_dict(row, "static_attenuation", mesh_static_att_lineEdit.text()))

    mesh_receiving_port_label = QtWidgets.QLabel(parent=mesh_tab)
    mesh_receiving_port_label.setGeometry(QtCore.QRect(10, 80, 130, 21))
    mesh_receiving_port_label.setObjectName("mesh_receiving_port_label")
    mesh_receiving_port_label.setText("Receiving Port:")

    mesh_receiving_port_lineEdit = QtWidgets.QLineEdit(parent=mesh_tab)
    mesh_receiving_port_lineEdit.setGeometry(QtCore.QRect(150, 80, 61, 21))
    mesh_receiving_port_lineEdit.setObjectName("mesh_receiving_port_lineEdit")
    mesh_receiving_port_lineEdit.textChanged.connect(lambda: self.update_mesh_dict(row, "receiving_port", mesh_receiving_port_lineEdit.text()))

    # Output label and text
    mesh_output_label = QtWidgets.QLabel(parent=mesh_tab)
    mesh_output_label.setGeometry(QtCore.QRect(420, 10, 80, 21))
    mesh_output_label.setObjectName("mesh_output_label")
    mesh_output_label.setText("Output:")

    mesh_output_textEdit = QtWidgets.QTextEdit(parent=mesh_tab)
    mesh_output_textEdit.setGeometry(QtCore.QRect(420, 30, 321, 331))
    mesh_output_textEdit.setObjectName("mesh_output_textEdit")
    mesh_output_textEdit.setReadOnly(True)


    return mesh_top_tab

