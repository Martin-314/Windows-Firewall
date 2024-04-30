from time import sleep
import flet as ft
import ipaddress
import os
import subprocess
from flet_core import AlertDialog


def main(page: ft.Page):

    def Load_splash():
        page.splash = ft.Image(src='assets/splash.png')
        page.update()
        sleep(0.6)
        page.splash = None
        page.update()

    def Add_RemoteIP_Rule(e):
        if any(value is None for value in
               (
                       ActionDropdown.value, DirectionDropdown.value, IP_Address_TextField.value,
                       AddFirewall_TextField.value)):
            page.dialog = EmptyParameter_Dialog
            EmptyParameter_Dialog.open = True
            page.update()
        else:
            def validate_ip_address(ip_string):
                try:
                    ip_object = ipaddress.ip_address(ip_string)

                    r = subprocess.run(
                        args=['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                              f'name={AddFirewall_TextField.value}',
                              f'action={ActionDropdown.value.lower()}',
                              f'dir={DirectionDropdown.value.lower()}',
                              f'remoteip={IP_Address_TextField.value}'],
                        capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW
                    )

                    if 'Ok' in r.stdout:
                        page.dialog = Successful_Dialog
                        Successful_Dialog.open = True
                        RemoteIP_Chip_Clicked(e)
                        page.update()

                    elif 'The requested operation requires elevation' in r.stdout:
                        page.dialog = ElevatePrivilege_Dialog
                        ElevatePrivilege_Dialog.open = True
                        RemoteIP_Chip_Clicked(e)
                        page.update()

                    elif 'One or more essential parameters' in r.stdout:
                        page.dialog = EmptyParameter_Dialog
                        EmptyParameter_Dialog.open = True
                        page.update()

                except ValueError:
                    page.dialog = InvalidIP_Dialog
                    InvalidIP_Dialog.open = True
                    page.update()

            validate_ip_address(IP_Address_TextField.value)

    def Reset_firewall(e):
        print("reset done")
        page.dialog = Successful_Dialog
        Successful_Dialog.open = True
        page.update()

    def Add_Port_Rule(e):
        if any(value is None for value in
               (
                       ActionDropdown.value, DirectionDropdown.value, SecurityDropdown.value,
                       AddFirewall_TextField.value, PortNumber_TextField.value, ProtocolDropdown.value)):
            page.dialog = EmptyParameter_Dialog
            EmptyParameter_Dialog.open = True
            page.update()
        else:
            r = subprocess.run(
                args=['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                      f'name={AddFirewall_TextField.value}',
                      f'action={ActionDropdown.value.lower()}',
                      f'dir={DirectionDropdown.value.lower()}',
                      f'protocol={ProtocolDropdown.value.lower()}',
                      f'security={SecurityDropdown.value}'],
                capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW
            )

            if 'Ok' in r.stdout:
                page.dialog = Successful_Dialog
                Successful_Dialog.open = True
                Port_Chip_Clicked(e)
                page.update()

            elif 'The requested operation requires elevation' in r.stdout:
                page.dialog = ElevatePrivilege_Dialog
                ElevatePrivilege_Dialog.open = True
                Port_Chip_Clicked(e)
                page.update()

            elif "Block action was specified" in r.stdout:
                page.dialog = InvalidBlock_Action_Dialog
                InvalidBlock_Action_Dialog.open = True
                page.update()

            elif 'One or more essential parameters' in r.stdout:
                page.dialog = EmptyParameter_Dialog
                EmptyParameter_Dialog.open = True
                page.update()

    def Add_Program_Rule(e):
        if any(value is None for value in
               (
                       ActionDropdown.value, DirectionDropdown.value, SecurityDropdown.value,
                       AddFirewall_TextField.value, Path_TextField.value)):
            page.dialog = EmptyParameter_Dialog
            EmptyParameter_Dialog.open = True
            page.update()
        else:
            r = subprocess.run(
                args=['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                      f'name={AddFirewall_TextField.value}',
                      f'action={ActionDropdown.value.lower()}',
                      f'dir={DirectionDropdown.value.lower()}',
                      f'program={Path_TextField.value}',
                      f'security={SecurityDropdown.value}'],
                capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW
            )

            if 'Ok' in r.stdout:
                page.dialog = Successful_Dialog
                Successful_Dialog.open = True
                Program_Chip_Clicked(e)
                page.update()

            elif 'The requested operation requires elevation' in r.stdout:
                page.dialog = ElevatePrivilege_Dialog
                ElevatePrivilege_Dialog.open = True
                Program_Chip_Clicked(e)
                page.update()

            elif "Block action was specified" in r.stdout:
                page.dialog = InvalidBlock_Action_Dialog
                InvalidBlock_Action_Dialog.open = True
                page.update()
            elif 'The application contains':
                page.dialog = InvalidPath_Dialog
                InvalidPath_Dialog.open = True
                page.update()

            if 'One or more essential parameters' in r.stdout:
                page.dialog = EmptyParameter_Dialog
                EmptyParameter_Dialog.open = True
                page.update()

    def DeleteFirewall_Rule(e):
        if not DeleteFirewall_TextField.value:
            page.dialog = EmptyParameter_Dialog
            EmptyParameter_Dialog.open = True
            page.update()
        else:
            del_rule = subprocess.run(
                args=[
                    'netsh', 'advfirewal', 'firewall', 'delete', 'rule', f'name={DeleteFirewall_TextField.value}'
                ],
                shell=False, capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW
            )

            if 'Ok' in del_rule.stdout:
                page.dialog = Successful_Dialog
                Successful_Dialog.open = True
                RestoreFirewall_Fields()
                page.update()

            elif 'No rules match the specified criteria.' in del_rule.stdout:
                page.dialog = InvalidRule_Dialog
                InvalidRule_Dialog.open = True
                RestoreFirewall_Fields()
                page.update()

            elif 'The requested operation requires elevation' in del_rule.stdout:
                page.dialog = ElevatePrivilege_Dialog
                ElevatePrivilege_Dialog.open = True
                RestoreFirewall_Fields()
                page.update()

    def Backup_Firewall_Policy(e):
        page.dialog = Progress_Dialog
        Progress_Dialog.open = True
        page.update()

        backup_file = f'{desktop_path}{policy_file}'

        if os.path.exists(backup_file):
            os.remove(backup_file)

        r = subprocess.run(
            args=['netsh', 'advfirewall', 'export', f'{desktop_path}{policy_file}'],
            capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW
        )
        # print(r.stdout)

        if 'Ok.' in r.stdout:
            Progress_Dialog.open = False
            page.update()

            page.dialog = Successful_Dialog
            Successful_Dialog.open = True
            page.update()

            page.overlay.append(PolicyBackup_BottomSheet)
            page.update()
            PolicyBackup_BottomSheet.open = True
            PolicyBackup_BottomSheet.update()

        elif 'The requested operation requires' in r.stdout:
            Progress_Dialog.open = False
            page.update()
            page.dialog = ElevatePrivilege_Dialog
            ElevatePrivilege_Dialog.open = True
            page.update()

    def Show_DeleteFirewall_TextField(e):
        if e.data == "true":
            DeleteFirewall_TextField.visible = True
            DeleteFirewall_TextField.update()
        else:
            DeleteFirewall_TextField.visible = False
            DeleteFirewall_TextField.update()

    def pick_files_result(e: ft.FilePickerResultEvent):
        if e.files:
            ", ".join(map(lambda f: f.name, e.files))
            # print(e.files[0].path)
            import_file = str(e.files[0].path)
            if not import_file.endswith('.wfw'):
                print('invalid file')
        else:
            print("Cancelled!")

    pick_files_dialog = ft.FilePicker(on_result=pick_files_result)

    page.overlay.append(pick_files_dialog)

    def RestoreFirewall_Fields():
        ProtocolDropdown.visible = True
        Path_TextField.visible = True
        PortNumber_TextField.visible = True
        SecurityDropdown.visible = True
        DirectionDropdown.visible = True
        IP_Address_TextField.visible = True
        ProtocolDropdown.value = None
        Path_TextField.value = None
        PortNumber_TextField.value = None
        SecurityDropdown.value = None
        DirectionDropdown.value = None
        ActionDropdown.value = None
        IP_Address_TextField.value = None
        AddFirewall_TextField.value = None
        DeleteFirewall_TextField.value = None
        RemoteIP_Chip.disabled = False
        LocalIP_Chip.disabled = False
        Port_Chip.disabled = False
        Program_Chip.disabled = False
        RemoteIP_AddButton.visible = False
        LocalIP_AddButton.visible = False
        Port_AddButton.visible = False
        Program_AddButton.visible = False

    def RemoteIP_Chip_Clicked(e):
        RestoreFirewall_Fields()
        if not RemoteIP_Chip.selected:
            ProtocolDropdown.visible = False
            Path_TextField.visible = False
            PortNumber_TextField.visible = False
            SecurityDropdown.visible = False
            DirectionDropdown.visible = True
            IP_Address_TextField.visible = True
            RemoteIP_AddButton.visible = True
            RemoteIP_Chip.selected = True
            LocalIP_Chip.disabled = True
            Port_Chip.disabled = True
            Program_Chip.disabled = True
            page.update()
        else:
            RestoreFirewall_Fields()
            RemoteIP_Chip.selected = False
            page.update()

    def LocalIP_Chip_Clicked(e):
        RestoreFirewall_Fields()
        if not LocalIP_Chip.selected:
            ProtocolDropdown.visible = False
            Path_TextField.visible = False
            PortNumber_TextField.visible = False
            SecurityDropdown.visible = False
            DirectionDropdown.visible = True
            IP_Address_TextField.visible = True
            LocalIP_AddButton.visible = True
            LocalIP_Chip.selected = True
            RemoteIP_Chip.disabled = True
            Port_Chip.disabled = True
            Program_Chip.disabled = True
            page.update()
        else:
            RestoreFirewall_Fields()
            LocalIP_Chip.selected = False
            page.update()

    def Port_Chip_Clicked(e):
        RestoreFirewall_Fields()
        if not Port_Chip.selected:
            ProtocolDropdown.visible = True
            Path_TextField.visible = False
            PortNumber_TextField.visible = True
            SecurityDropdown.visible = True
            DirectionDropdown.visible = True
            IP_Address_TextField.visible = False
            Port_AddButton.visible = True
            Port_Chip.selected = True
            RemoteIP_Chip.disabled = True
            LocalIP_Chip.disabled = True
            Program_Chip.disabled = True
            page.update()
        else:
            RestoreFirewall_Fields()
            Port_Chip.selected = False
            page.update()

    def Program_Chip_Clicked(e):
        RestoreFirewall_Fields()
        if not Program_Chip.selected:
            ProtocolDropdown.visible = False
            Path_TextField.visible = True
            PortNumber_TextField.visible = False
            SecurityDropdown.visible = True
            DirectionDropdown.visible = True
            IP_Address_TextField.visible = False
            Program_AddButton.visible = True
            Program_Chip.selected = True
            RemoteIP_Chip.disabled = True
            LocalIP_Chip.disabled = True
            Port_Chip.disabled = True
            page.update()
        else:
            RestoreFirewall_Fields()
            Program_Chip.selected = False
            page.update()

    def Close_Dialogs(e):
        ElevatePrivilege_Dialog.open = False
        InvalidPath_Dialog.open = False
        InvalidIP_Dialog.open = False
        InvalidBlock_Action_Dialog.open = False
        EmptyParameter_Dialog.open = False
        Successful_Dialog.open = False
        DeleteFirewall_Dialog.open = False
        comfirmation_dialog.open = False
        ResetFirewall_Dialog.open = False
        page.update()

    def Delete_Cation(e):
        page.dialog = DeleteFirewall_Dialog
        DeleteFirewall_Dialog.open = True
        page.update()

    def Reset_Cation(e):
        page.dialog = ResetFirewall_Dialog
        ResetFirewall_Dialog.open = True
        page.update()


    ###########Dialogs########################

    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    policy_file: str = r'\FirewallPolicy.wfw'
    reset_policy_file: str = r'\backuppolicy.wfw'

    DeleteFirewall_Dialog: AlertDialog = ft.AlertDialog(
        title=ft.Row(
            controls=[
                ft.Icon(
                    name=ft.icons.WARNING_ROUNDED,
                    color=ft.colors.YELLOW_800, size=35
                ),
                ft.Text('Cation')
            ]
        ),
        content=ft.Text(f'Are you sure your want to delete this rule'),
        actions=[
            ft.Row(
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                controls=[
                    ft.TextButton(text="Cancel", on_click=Close_Dialogs),
                    ft.TextButton(text="Confirm", on_click=DeleteFirewall_Rule),
                ]
            )
        ]
    )

    ResetFirewall_Dialog: AlertDialog = ft.AlertDialog(
        title=ft.Row(
            controls=[
                ft.Icon(
                    name=ft.icons.WARNING_ROUNDED,
                    color=ft.colors.YELLOW_800, size=35
                ),
                ft.Text('Cation')
            ]
        ),
        content=ft.Text(f'Are you sure your want to reset firewall policies'),
        actions=[
            ft.Row(
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                controls=[
                    ft.TextButton(text="Cancel", on_click=Close_Dialogs),
                    ft.TextButton(text="Confirm", on_click=Reset_firewall),
                ]
            )
        ]
    )

    comfirmation_dialog = ft.AlertDialog(
        title=ft.Row(
            controls=[
                ft.Icon(
                    name=ft.icons.WARNING_ROUNDED,
                    color=ft.colors.YELLOW_800, size=35
                ),
                ft.Text('Cation')
            ]
        ),
        content=ft.Text(f'This Change may require a system restart'),
        actions=[
            ft.Row(
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                controls=[
                    ft.TextButton(text="Cancel", on_click=Close_Dialogs),
                    ft.TextButton(text="Confirm"),
                ]
            )
        ]
    )

    EmptyParameter_Dialog: AlertDialog = ft.AlertDialog(
        title=ft.Row(
            controls=[
                ft.Icon(
                    name=ft.icons.ERROR,
                    color=ft.colors.RED_800, size=35
                ),
                ft.Text('Error.')
            ]
        ),
        content=ft.Text('All parameters must be filled.'),
        actions_alignment=ft.MainAxisAlignment.CENTER,
        actions=[ft.TextButton(text="Dismiss", on_click=Close_Dialogs)]
    )

    InvalidIP_Dialog = ft.AlertDialog(
        title=ft.Row(
            controls=[
                ft.Icon(
                    name=ft.icons.ERROR,
                    color=ft.colors.RED_800, size=35
                ),
                ft.Text('Error.')
            ]
        ),
        content=ft.Text('Invalid IP'),
        actions_alignment=ft.MainAxisAlignment.CENTER,
        actions=[ft.TextButton(text="Dismiss", on_click=Close_Dialogs)]
    )

    InvalidBlock_Action_Dialog = ft.AlertDialog(
        title=ft.Row(
            controls=[
                ft.Icon(
                    name=ft.icons.ERROR,
                    color=ft.colors.RED_800, size=35
                ),
                ft.Text('Error.')
            ]
        ),
        content=ft.Text('Block action can not be used in conjunction\n'
                        'with require security or require encryption.'),
        actions_alignment=ft.MainAxisAlignment.CENTER,
        actions=[ft.TextButton(text="Dismiss", on_click=Close_Dialogs)]
    )

    InvalidPath_Dialog = ft.AlertDialog(
        title=ft.Row(
            controls=[
                ft.Icon(
                    name=ft.icons.ERROR,
                    color=ft.colors.RED_800, size=35
                ),
                ft.Text('Error.')
            ]
        ),
        content=ft.Text('The application contains invalid \n'
                        'characters, or is an invalid length.'),
        actions_alignment=ft.MainAxisAlignment.CENTER,
        actions=[ft.TextButton(text="Dismiss", on_click=Close_Dialogs)]
    )

    InvalidRule_Dialog = ft.AlertDialog(
        title=ft.Row(
            controls=[
                ft.Icon(
                    name=ft.icons.ERROR,
                    color=ft.colors.RED_800, size=35
                ),
                ft.Text('Error.')
            ]
        ),
        content=ft.Text('No rules match the specified criteria.'),
        actions_alignment=ft.MainAxisAlignment.CENTER,
        actions=[ft.TextButton(text="Dismiss", on_click=Close_Dialogs)]
    )

    Progress_Dialog = ft.AlertDialog(
        content=ft.Row(width=50, height=50, controls=[ft.ProgressRing()]),
        content_padding=ft.padding.only(left=110, right=100, top=40, bottom=20),
        actions_alignment=ft.MainAxisAlignment.CENTER,
        actions=[ft.Text('Do not disrupt this process')],
        modal=True
    )

    ElevatePrivilege_Dialog: AlertDialog = ft.AlertDialog(
        title=ft.Row(
            controls=[
                ft.Icon(
                    name=ft.icons.CANCEL_OUTLINED,
                    color=ft.colors.RED_800, size=35
                ),
                ft.Text('Permission denied.')
            ]
        ),
        content=ft.Text('You must run application with\n'
                        'administrator privilege.'),
        actions_alignment=ft.MainAxisAlignment.CENTER,
        actions=[ft.TextButton(text="Dismiss", on_click=Close_Dialogs)]
    )

    Successful_Dialog = ft.AlertDialog(
        title=ft.Text('Done'),
        title_padding=ft.padding.only(left=110, right=100, top=15),
        content=ft.Icon(
            name=ft.icons.CHECK_CIRCLE_OUTLINE_ROUNDED,
            color=ft.colors.GREEN, size=50
        ),
        actions_alignment=ft.MainAxisAlignment.CENTER,
        actions=[ft.TextButton(text="Dismiss", on_click=Close_Dialogs)]
    )

    PolicyBackup_BottomSheet = ft.BottomSheet(
        open=True,
        content=ft.Container(
            width=850,
            height=100,
            padding=ft.padding.only(left=150, right=100, top=20),
            content=ft.Column(
                expand=True,
                controls=[
                    ft.Text(value='Your Policy Backup is ready at', weight=ft.FontWeight.W_500),
                    ft.Text(
                        value=f'{desktop_path}{policy_file}', selectable=True,
                        weight=ft.FontWeight.W_600
                    )
                ]
            )
        ),
        dismissible=True
    )

    #########################################

    DeleteFirewall_TextField = ft.TextField(
        width=200,
        height=55,
        border_radius=22,
        border_width=2,
        content_padding=10,
        label="Rule Name",
        visible=False
    )
    AddFirewall_TextField = ft.TextField(
        width=200,
        height=50,
        text_size=16,
        border_radius=22,
        border_width=2,
        content_padding=10,
        label="Rule Name",
        visible=True
    )
    IP_Address_TextField = ft.TextField(
        width=200,
        height=50,
        text_size=16,
        border_radius=22,
        border_width=2,
        content_padding=10,
        label="Address",
        visible=True
    )
    PortNumber_TextField = ft.TextField(
        width=70,
        height=50,
        text_size=16,
        border_radius=22,
        border_width=2,
        content_padding=10,
        input_filter=ft.NumbersOnlyInputFilter(),
        label="Port",
        visible=True
    )
    Path_TextField = ft.TextField(
        width=420,
        height=50,
        text_size=16,
        border_radius=22,
        border_width=2,
        content_padding=10,
        label="Path",
        visible=True
    )
    ProtocolDropdown = ft.Dropdown(
        label="Protocol",
        width=110,
        height=50,
        text_size=16,
        border_radius=20,
        border_width=2,
        content_padding=10,
        visible=True,
        options=[
            ft.dropdown.Option("TCP"),
            ft.dropdown.Option("UDP"),
            ft.dropdown.Option("Any"),
        ],
    )
    DirectionDropdown = ft.Dropdown(
        label="Direction",
        width=110,
        height=50,
        text_size=16,
        border_radius=20,
        border_width=2,
        content_padding=10,
        visible=True,
        options=[
            ft.dropdown.Option("In"),
            ft.dropdown.Option("Out"),
        ],
    )
    ActionDropdown = ft.Dropdown(
        label="Action",
        width=110,
        height=50,
        text_size=16,
        border_radius=20,
        border_width=2,
        content_padding=10,
        visible=True,
        options=[
            ft.dropdown.Option("Allow"),
            ft.dropdown.Option("Block"),
            ft.dropdown.Option("Bypass"),
        ],
    )
    SecurityDropdown = ft.Dropdown(
        label="Security",
        width=135,
        height=50,
        text_size=16,
        border_radius=20,
        border_width=2,
        content_padding=10,
        visible=True,
        options=[
            ft.dropdown.Option("authenticate"),
            ft.dropdown.Option("authenc"),
            ft.dropdown.Option("authdynenc"),
            ft.dropdown.Option("authnoencap"),
            ft.dropdown.Option("notrequired"),
        ],
    )

    RemoteIP_Chip = ft.Chip(
        label=ft.Text("Remote IP"),
        bgcolor=ft.colors.INVERSE_PRIMARY,
        disabled_color=ft.colors.SURFACE_VARIANT,
        selected_color=ft.colors.PRIMARY_CONTAINER,
        autofocus=True,
        on_click=RemoteIP_Chip_Clicked,
        # on_delete=amenity_unselected
    )

    LocalIP_Chip = ft.Chip(
        label=ft.Text("Local IP"),
        bgcolor=ft.colors.INVERSE_PRIMARY,
        disabled_color=ft.colors.SURFACE_VARIANT,
        selected_color=ft.colors.BLUE_200,
        autofocus=True,
        on_click=LocalIP_Chip_Clicked,
    )

    Port_Chip = ft.Chip(
        label=ft.Text("Port"),
        bgcolor=ft.colors.BLUE_ACCENT_200,
        disabled_color=ft.colors.SURFACE_VARIANT,
        selected_color=ft.colors.BLUE_200,
        autofocus=True,
        on_click=Port_Chip_Clicked,
        # shape=ft.RoundedRectangleBorder(radius=6),
    )

    Program_Chip = ft.Chip(
        label=ft.Text("Program"),
        bgcolor=ft.colors.BLUE_ACCENT_200,
        disabled_color=ft.colors.SURFACE_VARIANT,
        selected_color=ft.colors.BLUE_200,
        autofocus=True,
        on_click=Program_Chip_Clicked,
    )

    RemoteIP_AddButton = ft.FilledButton(
        height=50,
        width=75,
        text="Add",
        visible=False,
        on_click=Add_RemoteIP_Rule
    )

    LocalIP_AddButton = ft.FilledButton(
        height=50,
        width=75,
        text="Add",
        visible=False,
        on_click=DeleteFirewall_Rule
    )

    Port_AddButton = ft.FilledButton(
        height=50,
        width=75,
        text="Add",
        visible=False,
        on_click=Add_Port_Rule
    )

    Program_AddButton = ft.FilledButton(
        height=50,
        width=75,
        text="Add",
        visible=False,
        on_click=Add_Program_Rule
    )

    n = ft.Container(
        height=270, bgcolor=ft.colors.SURFACE_VARIANT, border_radius=10,
        padding=20,
        content=ft.Column(
            controls=[
                ft.Text('Add Rule'),
                ft.Row(
                    controls=[
                        LocalIP_Chip,
                        RemoteIP_Chip,
                        Port_Chip,
                        Program_Chip
                    ]
                ),
                ft.Container(height=10, border_radius=20),
                ft.Row(
                    wrap=True,
                    controls=[
                        AddFirewall_TextField,
                        ProtocolDropdown,
                        DirectionDropdown,
                        ActionDropdown,
                        PortNumber_TextField,
                        IP_Address_TextField,
                        SecurityDropdown,
                        Path_TextField,
                        RemoteIP_AddButton,
                        LocalIP_AddButton,
                        Port_AddButton,
                        Program_AddButton

                    ]
                ),

            ]
        )
    )

    l = ft.Container(
        height=80, bgcolor=ft.colors.SURFACE_VARIANT, border_radius=10,
        padding=ft.padding.only(left=20, right=20),
        on_hover=Show_DeleteFirewall_TextField,
        content=ft.Row(
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            controls=[
                ft.Text('Delete Rule'),
                DeleteFirewall_TextField,
                ft.ElevatedButton(
                    width=96,
                    text="Delete",
                    style=ft.ButtonStyle(color=ft.colors.WHITE, bgcolor=ft.colors.RED_500),
                    on_click=Delete_Cation,
                )

            ]
        )
    )

    t = ft.Container(
        height=80, bgcolor=ft.colors.SURFACE_VARIANT, border_radius=10,
        padding=ft.padding.only(left=20, right=20),
        content=ft.Row(
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            controls=[
                ft.Text(value="Export Policy"),
                ft.FilledButton(text="Export", on_click=Backup_Firewall_Policy)
            ]
        )
    )

    y = ft.Container(
        height=80, bgcolor=ft.colors.SURFACE_VARIANT, border_radius=10,
        padding=ft.padding.only(left=20, right=20),
        content=ft.Row(
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            controls=[
                ft.Text(value="Import Policy"),
                ft.FilledButton(text="Import", on_click=lambda _: pick_files_dialog.pick_files(allow_multiple=True))
            ]
        )
    )

    j = ft.Container(
        height=80, bgcolor=ft.colors.SURFACE_VARIANT, border_radius=10,
        padding=ft.padding.only(left=20, right=20),
        # on_hover=Show_DeleteFirewall_TextField,
        content=ft.Row(
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            controls=[
                ft.Text('Reset firewall Policy'),
                ft.ElevatedButton(
                    width=96,
                    text="Reset",
                    style=ft.ButtonStyle(color=ft.colors.WHITE, bgcolor=ft.colors.RED_500),
                    on_click=Reset_Cation,
                )

            ]
        )
    )

    Load_splash()
    page.add(n, l, t, y, j)
    page.window_min_width = 870
    # page.theme = ft.Theme(color_scheme_seed="green")
    # page.theme_mode = 'dark'
    page.scroll = ft.ScrollMode.HIDDEN
    page.update()


ft.app(target=main, assets_dir="assets")