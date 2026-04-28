sudo umount /mnt/raid_test 2>/dev/null
sudo mdadm --stop /dev/md0 2>/dev/null
sudo losetup -D  # Odłączy wszystkie urządzenia loop

# 3 pliki po 200MB (RAID 5 da nam ~400MB przestrzeni na dane)
truncate -s 200M diskA.raw
truncate -s 200M diskB.raw
truncate -s 200M diskC.raw

# Podpięcie pod system
sudo losetup -P /dev/loop20 diskA.raw
sudo losetup -P /dev/loop21 diskB.raw
sudo losetup -P /dev/loop22 diskC.raw

# for dev in /dev/loop20 /dev/loop21 /dev/loop22; do
#     sudo sgdisk -n 1:2048:0 -t 1:fd00 $dev
# done
# Odświeżenie informacji o partycjach
sudo partprobe /dev/loop20 /dev/loop21 /dev/loop22

#sudo mdadm --create /dev/md0 --level=5 --raid-devices=3 /dev/loop20p1 /dev/loop21p1 /dev/loop22p1
sudo mdadm --create /dev/md0 --level=5 --raid-devices=3 /dev/loop20 /dev/loop21 /dev/loop22

# Formatowanie i montowanie
sudo mkfs.ext4 /dev/md0
sudo mkdir -p /mnt/raid_test
sudo mount /dev/md0 /mnt/raid_test

# Wrzucanie danych - pobierzmy przykładowe pliki z sieci lub skopiuj swoje
sudo wget -P /mnt/raid_test/ https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf
sudo wget -O /mnt/raid_test/test_image.jpg https://upload.wikimedia.org/wikipedia/commons/4/47/PNG_transparency_demonstration_1.png
sudo touch /mnt/raid_test/dokument_firmowy.doc
sudo bash -c "echo 'Tajne dane forensics' > /mnt/raid_test/notatka.txt"

# Ważne: odmontowanie i zatrzymanie, aby zapisać metadane
sudo umount /mnt/raid_test
sudo mdadm --stop /dev/md0
sudo losetup -d /dev/loop20 /dev/loop21 /dev/loop22

ewfacquire -t disk_forensic_A -f encase6 diskA.raw
ewfacquire -t disk_forensic_B -f encase6 diskB.raw
ewfacquire -t disk_forensic_C -f encase6 diskC.raw