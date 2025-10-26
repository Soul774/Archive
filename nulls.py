import keyboard as kb

holding_space = False
holding_a = False
holding_d = False
holding_s = False
holding_w = False

def on_space_press(e):
    global holding_space, current_style
    holding_space = True
    if holding_w:
        kb.release('w')

def on_a_press(e):
    global holding_a
    holding_a = True
    if holding_d:
        kb.release('d')

def on_a_release(e):
    global holding_a
    holding_a = False
    if holding_d:
        kb.press('d')

def on_d_press(e):
    global holding_d
    holding_d = True
    if holding_a:
        kb.release('a')

def on_d_release(e):
    global holding_d
    holding_d = False
    if holding_a:
        kb.press('a')

def on_s_press(e):
    global holding_s
    holding_s = True
    if holding_w:
        kb.release('w')

def on_s_release(e):
    global holding_s
    holding_s = False
    if holding_w:
        kb.press('w')

def on_w_press(e):
    global holding_w
    holding_w = True
    if holding_s:
        kb.release('s')

def on_w_release(e):
    global holding_w
    holding_w = False
    if holding_s:
        kb.press('s')

kb.on_press_key('space', on_space_press)
kb.on_press_key('a', on_a_press)
kb.on_release_key('a', on_a_release)
kb.on_press_key('d', on_d_press)
kb.on_release_key('d', on_d_release)
kb.on_press_key('s', on_s_press)
kb.on_release_key('s', on_s_release)
kb.on_press_key('w', on_w_press)
kb.on_release_key('w', on_w_release)

kb.wait()