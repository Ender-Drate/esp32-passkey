import bpy
import bmesh
import math
import os
from mathutils import Vector

# ---------------------------------------------------------------------------
# TechXPassKey breadboard-size enclosures (units = millimetres)
# Outer footprint: 54.1 x 81.6 mm, height 26 mm
# ---------------------------------------------------------------------------
OUT_W, OUT_D = 54.1, 81.6
H = 26.0
WALL = 2.0
FLOOR = 2.0
LID = 2.0
BASE_H = H - LID
IN_W = OUT_W - 2 * WALL
IN_D = OUT_D - 2 * WALL
R_OUT = 4.0
R_IN = 2.0

OUT_DIR = os.environ.get("PK_ENCLOSURE_DIR", r"D:\dsh_Workspaces\ESP32\projects\passkey\enclosure")
os.makedirs(OUT_DIR, exist_ok=True)


def clear_scene():
    bpy.ops.object.select_all(action="SELECT")
    bpy.ops.object.delete(use_global=False)
    for block in (bpy.data.meshes, bpy.data.curves, bpy.data.materials):
        for item in list(block):
            if item.users == 0:
                block.remove(item)


def activate(obj):
    bpy.ops.object.select_all(action="DESELECT")
    obj.select_set(True)
    bpy.context.view_layer.objects.active = obj


def apply_mod(obj, mod):
    activate(obj)
    bpy.ops.object.modifier_apply(modifier=mod.name)


def rounded_prism(name, w, d, h, r, z0, segments=6):
    bm = bmesh.new()
    bmesh.ops.create_cube(bm, size=2.0)
    for v in bm.verts:
        v.co.x *= w / 2
        v.co.y *= d / 2
        v.co.z *= h / 2
    if r > 0:
        vertical = [e for e in bm.edges
                    if abs(e.verts[0].co.z - e.verts[1].co.z) > 1e-5]
        bmesh.ops.bevel(bm, geom=vertical, offset=r, offset_type="OFFSET",
                        segments=segments, profile=0.5, affect="EDGES",
                        clamp_overlap=True)
    me = bpy.data.meshes.new(name)
    bm.to_mesh(me)
    bm.free()
    obj = bpy.data.objects.new(name, me)
    bpy.context.collection.objects.link(obj)
    obj.location = (0, 0, z0 + h / 2)
    return obj


def box(name, w, d, h, loc):
    bm = bmesh.new()
    bmesh.ops.create_cube(bm, size=2.0)
    for v in bm.verts:
        v.co.x *= w / 2
        v.co.y *= d / 2
        v.co.z *= h / 2
    me = bpy.data.meshes.new(name)
    bm.to_mesh(me)
    bm.free()
    obj = bpy.data.objects.new(name, me)
    bpy.context.collection.objects.link(obj)
    obj.location = loc
    return obj


def cylinder(name, r, depth, loc, axis="Z", vertices=64):
    rot = (0, 0, 0)
    if axis == "Y":
        rot = (math.radians(90), 0, 0)
    elif axis == "X":
        rot = (0, math.radians(90), 0)
    bpy.ops.mesh.primitive_cylinder_add(
        vertices=vertices, radius=r, depth=depth, location=loc, rotation=rot
    )
    obj = bpy.context.object
    obj.name = name
    return obj


def boolean(target, cutter, op="DIFFERENCE"):
    mod = target.modifiers.new("bool", "BOOLEAN")
    mod.operation = op
    mod.solver = "EXACT"
    mod.object = cutter
    apply_mod(target, mod)
    bpy.data.objects.remove(cutter, do_unlink=True)


def join(target, other):
    bpy.ops.object.select_all(action="DESELECT")
    target.select_set(True)
    other.select_set(True)
    bpy.context.view_layer.objects.active = target
    bpy.ops.object.join()


def smooth_bevel(obj, width=0.5, segments=2):
    mod = obj.modifiers.new("edge", "BEVEL")
    mod.width = width
    mod.segments = segments
    mod.limit_method = "ANGLE"
    mod.angle_limit = math.radians(50)
    apply_mod(obj, mod)


def recalc_normals(obj):
    activate(obj)
    bpy.ops.object.mode_set(mode="EDIT")
    bpy.ops.mesh.select_all(action="SELECT")
    bpy.ops.mesh.normals_make_consistent(inside=False)
    bpy.ops.object.mode_set(mode="OBJECT")


def export_stl(obj, path):
    activate(obj)
    try:
        bpy.ops.wm.stl_export(
            filepath=path,
            export_selected_objects=True,
            apply_modifiers=True,
            global_scale=1.0,
        )
    except Exception:
        bpy.ops.export_mesh.stl(
            filepath=path, use_selection=True, global_scale=1.0, apply_modifiers=True
        )


def make_label(text, y, z):
    bpy.ops.object.text_add(location=(0, y, z))
    obj = bpy.context.object
    obj.data.body = text
    obj.data.size = 8.5
    obj.data.extrude = 0.0
    obj.data.align_x = "CENTER"
    obj.data.align_y = "CENTER"
    obj.data.space_character = 1.0
    font_path = r"C:\Windows\Fonts\arialbd.ttf"
    if os.path.exists(font_path):
        obj.data.font = bpy.data.fonts.load(font_path)
    bpy.ops.object.convert(target="MESH")
    obj = bpy.context.object
    obj.name = "label_" + text
    solid = obj.modifiers.new("solid", "SOLIDIFY")
    solid.thickness = 0.6
    solid.offset = 0.0
    apply_mod(obj, solid)
    return obj


def build_case(tag, label, material_base, material_lid):
    # Base shell
    base = rounded_prism(tag + "_base", OUT_W, OUT_D, BASE_H, R_OUT, 0)
    cavity = rounded_prism(tag + "_cavity", IN_W, IN_D, BASE_H - FLOOR + 2, R_IN, FLOOR)
    boolean(base, cavity)

    # M3 bosses
    for sx in (-21.0, 21.0):
        for sy in (-33.0, 33.0):
            boss = cylinder(tag + "_boss", 3.0, 20.0, (sx, sy, 12.0), "Z")
            boolean(base, boss, "UNION")
            pilot = cylinder(tag + "_pilot", 1.3, 18.0, (sx, sy, 11.0), "Z")
            boolean(base, pilot)

    # Board rails: 25.4 mm board, 64 mm long, sits at z=10
    for sx in (-14.2, 14.2):
        rail = box(tag + "_rail", 2.0, 64.0, 4.0, (sx, 0, 8.0))
        boolean(base, rail, "UNION")
        lip = box(tag + "_lip", 1.2, 64.0, 1.4,
                  (13.4 if sx > 0 else -13.4, 0, 10.7))
        boolean(base, lip, "UNION")
    stop = box(tag + "_stop", 28.0, 2.0, 4.0, (0, 32.0, 8.0))
    boolean(base, stop, "UNION")

    # USB-C opening on -Y: 12 x 6 mm
    usb = box(tag + "_usb", 12.0, 10.0, 6.0, (0, -OUT_D / 2, 9.5))
    boolean(base, usb)

    # DC barrel pass-through on +Y: 8 mm circle + 5.6 mm slot open to floor
    dc_hole = cylinder(tag + "_dc", 4.0, 10.0, (0, OUT_D / 2, 14.0), "Y")
    dc_slot = box(tag + "_dc_slot", 5.6, 10.0, 14.5, (0, OUT_D / 2, 7.25))
    boolean(dc_hole, dc_slot, "UNION")
    boolean(base, dc_hole)

    # Keep the top rim flat at z=24 so the lid sits flush; no post-boolean
    # bevel on the shell (it would round away the 2 mm rim).
    recalc_normals(base)

    # Lid plate
    lid = rounded_prism(tag + "_lid", OUT_W, OUT_D, LID, R_OUT, BASE_H)
    # Friction lip: four bars, corners left open for the bosses
    bar_w = 1.8
    for sy in (-1, 1):
        bar = box(tag + "_lip_y", OUT_W - 2 * WALL - 0.4, bar_w, 4.0,
                  (0, sy * (OUT_D / 2 - WALL - bar_w / 2), BASE_H - 2))
        boolean(lid, bar, "UNION")
    for sx in (-1, 1):
        bar = box(tag + "_lip_x", bar_w, OUT_D - 2 * WALL - 0.4, 4.0,
                  (sx * (OUT_W / 2 - WALL - bar_w / 2), 0, BASE_H - 2))
        boolean(lid, bar, "UNION")

    # Lid screw holes + counterbores
    for sx in (-21.0, 21.0):
        for sy in (-33.0, 33.0):
            hole = cylinder(tag + "_screw", 1.7, 6.0, (sx, sy, H), "Z")
            boolean(lid, hole)
            cb = cylinder(tag + "_cb", 3.0, 1.4, (sx, sy, H - 0.6), "Z")
            boolean(lid, cb)

    # Button + reset access
    btn = cylinder(tag + "_btn", 2.6, 6.0, (0, -30.0, H), "Z")
    boolean(lid, btn)
    rst = cylinder(tag + "_rst", 1.1, 6.0, (12.0, -30.0, H), "Z")
    boolean(lid, rst)

    # Vent slots
    for x in (-15.0, -5.0, 5.0, 15.0):
        vent = box(tag + "_vent", 2.4, 9.0, 6.0, (x, 14.0, H))
        boolean(lid, vent)

    # Embossed label: keep the glyph shell crisp and join it to the lid; the
    # slicer unions the overlapping shells, while a boolean here tends to
    # collapse thin letter strokes.
    text = make_label(label, -6.0, H)
    join(lid, text)

    recalc_normals(lid)

    # The boolean/join can leave an empty slot 0; make the intended material
    # the only slot so Workbench renders the right colour.
    base.data.materials.clear()
    base.data.materials.append(material_base)
    lid.data.materials.clear()
    lid.data.materials.append(material_lid)
    return base, lid


def make_material(name, rgb, metallic=0.0, roughness=0.55):
    mat = bpy.data.materials.get(name) or bpy.data.materials.new(name)
    mat.use_nodes = True
    bsdf = mat.node_tree.nodes.get("Principled BSDF")
    if bsdf:
        bsdf.inputs["Base Color"].default_value = (*rgb, 1)
        bsdf.inputs["Metallic"].default_value = metallic
        bsdf.inputs["Roughness"].default_value = roughness
    mat.diffuse_color = (*rgb, 1)
    return mat


clear_scene()

mat_main_base = make_material("main_base", (0.055, 0.095, 0.16), 0.0, 0.5)
mat_main_lid = make_material("main_lid", (0.08, 0.13, 0.21), 0.0, 0.45)
mat_key_base = make_material("key_base", (0.05, 0.11, 0.09), 0.0, 0.5)
mat_key_lid = make_material("key_lid", (0.07, 0.16, 0.12), 0.0, 0.45)
mat_board = make_material("pcb", (0.02, 0.18, 0.10), 0.0, 0.6)
mat_cable = make_material("cable", (0.02, 0.02, 0.02), 0.0, 0.4)
mat_floor = make_material("floor", (0.72, 0.72, 0.75), 0.0, 0.8)

main_base, main_lid = build_case("main", "MAIN", mat_main_base, mat_main_lid)
key_base, key_lid = build_case("key", "KEY", mat_key_base, mat_key_lid)

# Export before moving to display positions
for obj, name in (
    (main_base, "main_base.stl"),
    (main_lid, "main_lid.stl"),
    (key_base, "key_base.stl"),
    (key_lid, "key_lid.stl"),
):
    export_stl(obj, os.path.join(OUT_DIR, name))

# Display layout: main assembled, key exploded, to show both the outside and
# the internal rails/bosses in one shot.
main_base.location = (-40, 0, 0)
key_base.location = (40, 0, 0)
main_lid.location = (-40, 0, BASE_H)
key_lid.location = (40, 0, 42)

# Exploded key lid tilt for a readable product shot
key_lid.rotation_euler = (math.radians(-12), 0, math.radians(8))

# PCB dummies inside both cases
pcb_main = box("pcb_main", 25.4, 52.0, 1.6, (-40, 0, 10.8))
pcb_main.data.materials.append(mat_board)
pcb_key = box("pcb_key", 25.4, 52.0, 1.6, (40, 0, 10.8))
pcb_key.data.materials.append(mat_board)

# USB-C and DC cable stubs
usb_stub = box("usb_stub", 8.5, 14.0, 3.2, (-40, -47.0, 9.5))
usb_stub.data.materials.append(mat_cable)
dc_stub = cylinder("dc_stub", 4.0, 20.0, (40, 47.0, 12.0), "Y")
dc_stub.data.materials.append(mat_cable)

# Ground
ground = box("ground", 300.0, 300.0, 2.0, (0, 0, -1.0))
ground.data.materials.append(mat_floor)

# Camera
bpy.ops.object.camera_add(location=(150, -190, 135))
cam = bpy.context.object
cam.data.type = "ORTHO"
cam.data.ortho_scale = 205.0
bpy.context.scene.camera = cam
# aim at scene center
direction = Vector((0, 0, 22)) - cam.location
cam.rotation_euler = direction.to_track_quat("-Z", "Y").to_euler()

# Workbench render
scene = bpy.context.scene
scene.render.engine = "BLENDER_WORKBENCH"
scene.display.shading.light = "STUDIO"
scene.display.shading.color_type = "MATERIAL"
scene.display.shading.show_shadows = True
scene.display.shading.show_cavity = True
scene.display.shading.cavity_type = "BOTH"
scene.display.shading.show_specular_highlight = True
scene.render.resolution_x = 1800
scene.render.resolution_y = 1100
scene.render.resolution_percentage = 100
scene.render.film_transparent = False
scene.world.color = (0.86, 0.87, 0.90)
scene.display.shading.background_type = "VIEWPORT"
scene.display.shading.background_color = (0.86, 0.87, 0.90)
scene.render.filepath = os.path.join(OUT_DIR, "preview.png")
bpy.ops.render.render(write_still=True)

# Second shot: both lids exploded, no PCB occlusion
main_lid.location.z = 42
main_lid.rotation_euler = (math.radians(-12), 0, math.radians(-8))
key_lid.location.z = 46
key_lid.rotation_euler = (math.radians(-14), 0, math.radians(10))
scene.render.filepath = os.path.join(OUT_DIR, "preview_exploded.png")
bpy.ops.render.render(write_still=True)

bpy.ops.wm.save_as_mainfile(filepath=os.path.join(OUT_DIR, "techxpasskey_enclosures.blend"))
print("OUT_DIR", OUT_DIR)
print("SIZES", OUT_W, OUT_D, H)
print("DONE")
