#!/usr/bin/python


import sys
import signal
import os
import math
import argparse
import subprocess
import boto
import boto.ec2
import time
import ConfigParser



def check_volume_attachment(dest):

    time.sleep(60)

    attached=False
    dir="/dev/xvdf"

    if debug:
        print "checking if volume is attached"

    while attached is False:

        command = "ssh -oStrictHostKeyChecking=no %s fedora@%s \"ls /dev/xvdf\"  " % (ssh_flags, dest)

        if debug:
            print command
        try:
            ret = subprocess.check_output(command, shell=True)
        except subprocess.CalledProcessError as err:
            msg="Something when wrong with ssh to %s " % err
            whine_and_die(msg)

        if debug:
            print "ls /dev/xvdf returned %s" % ret

        if ret.rstrip('\n')  == dir:
            attached=True
        else:
            time.sleep(10)



def whine_and_die(msg):
    print "%s" % msg
    exit(2)



def run_instance(instanceType):


    sshKey=keyName
    inst=conn.run_instances("ami-32427e5a", security_group_ids=[groupName], key_name=sshKey, instance_type=instanceType)
    instanceId = inst.instances[0]

    while (instanceId.state != 'running'):
        if debug:
            print "Current instance state: %s" % instanceId.state
        time.sleep(30)
        if instanceId.update() == 'pending':
            time.sleep(10)

    time.sleep(10)
    return instanceId




def create_volume(size, region):
    # size of the volume is 1.. but it should match or double the size of the directory


    newVolume = conn.create_volume(size, region)
    checkVolumeStatus = conn.get_all_volumes([newVolume.id])[0]
    while (checkVolumeStatus.status =='creating'):
        checkVolumeStatus = conn.get_all_volumes([newVolume.id])[0]
        time.sleep(10)


    return newVolume.id

def run_remote(command):
    if debug:
        print command


    try:
        ret = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)
    except subprocess.CalledProcessError as err:
        msg = "Something when wrong with %s to %s " % (command,ret)
        whine_and_die(msg)


def prep_backup_host(dest):


    if debug:
        print "Creating remote file system to backup %s" % dest
        print "to %s" % dest

    command = "ssh -oStrictHostKeyChecking=no %s fedora@%s \"sudo mkfs -F -t ext4 /dev/xvdf\"  " % (ssh_flags,dest)
    run_remote(command)

    command = "ssh -oStrictHostKeyChecking=no %s fedora@%s \"sudo mkdir /mnt/tmp_backup\"  " % (ssh_flags,dest)
    run_remote(command)

    command = "ssh -oStrictHostKeyChecking=no %s fedora@%s \"sudo mount /dev/xvdf /mnt/tmp_backup\"  " % (ssh_flags,dest)
    run_remote(command)

    command = "ssh -oStrictHostKeyChecking=no %s fedora@%s \"sudo chown fedora:fedora /mnt/tmp_backup\"  " %(ssh_flags, dest)
    run_remote(command)


def rsync_backup(dir,dest):

    if debug:
        print "Performing rsync backup of %s on %s" % (dir, dest)

    (dash,rsync_flags)= ssh_flags.split(' ')


    rsync_cmd = "rsync -rave \"ssh -i %s\"  %s fedora@%s:/mnt/tmp_backup/" %(os.path.expanduser(rsync_flags),dir,dest)
    run_remote(rsync_cmd)



def dd_backup(dir,dest):


    if debug:
        print "Performing dd backup of %s on %s" % (dir,dest)

    tarCmd = "tar cf - %s | ssh %s fedora@%s \"dd of=/mnt/tmp_backup/backup.tar\"" % (dir,ssh_flags,dest)
    run_remote(tarCmd)



def validate_size_directory(dir):

    size=0
    if (os.path.isdir(dir)):
        ret=subprocess.check_output(['du','-s',dir])
        out=ret.split()
        size=out[0]


    return int(size)


def calculate_volume_size(size):

    dir_size_GB = size * math.pow(10,-6)
    """Calculate volume size

    If the directory is less than 1GB set up a 2GB volume.
    Otherwise it is 2 * dir size in GB rounded up

    """
    if (dir_size_GB < 1):
        vol_size_GB=2
    else:
        vol_size_GB = int(round((2*dir_size_GB)))


    if (debug):
        print "Directory Size in GB %f" % dir_size_GB
        print "Setting Volume Size: %d" % vol_size_GB


    return vol_size_GB


def detach_volume(vol,inst):
    if debug:
        print "Detaching the volume %s " % vol
    detachVolume= conn.detach_volume(vol,inst.id,"/dev/xvdf")
    while (detachVolume == 'attached'):
        time.sleep(25)
    if debug:
        print "Detaching the volume %s " % vol


def stop_and_terminate_instance(inst):

    if debug:
        print"Process for stopping and terminating the instance:", inst.id
    conn.stop_instances (instance_ids=[inst.id])
    time.sleep(10)
    conn.terminate_instances(instance_ids=[inst.id])
    if debug:
        print"Shut down and terminate the instance:", inst.id

def create_Key_group():

    groupDescription="My security group CS615"
    sshPort=22
    cidrIp='0.0.0.0/0'

    try:
        KeyPair= conn.get_all_key_pairs(keynames=[keyName])[0]
    except conn.ResponseError, e:
        if e.code == 'InvalidKeyPair.NotFound':
            KeyPair = conn.create_key_pair(keyName)
            print 'A new key: %s' % keyName
            KeyPair.save(keyPath)
        else:
            pass
# creating group
    try:
        securityGroup = conn.get_all_security_groups(groupnames=[groupName])[0]
    except conn.ResponseError, e:
        if e.code == 'InvalidGroup.NotFound':
            securityGroup = conn.create_security_group(groupName, groupDescription)
            print 'A new security group : %s' % groupName
        else:
            pass

#adding rule:
    try:
        securityGroup.authorize(ip_protocol='tcp', from_port=sshPort, to_port=sshPort, cidr_ip=cidrIp)
    except conn.ResponseError, e:
        if e.code == 'InvalidPermission.Duplicate':
            print '%s is  authorized' % groupName
        else:
            pass





def exit_and_cleanup():
    try:
       cleanVol
    except NameError:
        if debug:
            print "Volume not created yet. Skipping"
        else:
            detach_volume(cleanVol,cleanInst)

    try:
        cleanInst
    except NameError:
        if debug:
            print "Instance not created yet. Skipping"
    else:
        stop_and_terminate_instance(cleanInst)


def signal_handler(signal,frame):

    print "Caught CTRL-C"
    exit_and_cleanup()
    sys.exit(0)



def main(argv):
    global debug
    global conn
    global keyName
    global keyPath
    global groupName
    global ssh_flags
    global cleanInst
    global cleanVol

    keyName = 'cs615'
    keyPath = '~/.ssh/'
    groupName = 'cs615'
    debug = False

    volume    = ''
    method    = ''
    directory = ''
    if 'EC2_BACKUP_VERBOSE' in os.environ:
        print "Enabling Debug mode"
        debug = True


    ssh_flags = os.environ.get('EC2_BACKUP_FLAGS_SSH')

    if ssh_flags is None:
        ssh_flags="-i %s%s" % (keyPath,keyName)
    else:
        parts = ssh_flags.split(' ')
        bname=os.path.split(parts[1])
        keyName=bname[1]

    if debug:
        print "Using key: %s" % keyName

    ssh_flags += ".pem"


    aws_config_file = os.environ.get('AWS_CONFIG_FILE')

    if aws_config_file is None:
        whine_and_die("Please set AWS_CONFIG_FILE environment variable to your aws configuration")

    config = ConfigParser.ConfigParser()

    try:
        with open(aws_config_file) as cf:
            config.readfp(cf)
    except IOError:
        whine_and_die("Failed to read %s" % aws_config_file)

    ACCESS_KEY = config.get('default', 'aws_access_key_id')
    SECRET_KEY = config.get('default', 'aws_secret_access_key')
    REGION     = config.get('default', 'region')


    conn = boto.ec2.connect_to_region(REGION, aws_access_key_id=ACCESS_KEY, aws_secret_access_key=SECRET_KEY)

    create_Key_group()

    parser = argparse.ArgumentParser(description='parse command line arguments')


    parser.add_argument('-m', help='Use the given method for the backup. Valid methods are "dd" and "rsync"; default is "dd"',
                        choices=['dd','rsync'],default='dd' )
    parser.add_argument('-v', help='Use the given volume instead of creating a new one' )
    parser.add_argument('dir',help='Directory to backup')

    args=parser.parse_args()
    directory=args.dir
    method=args.m
    volume=args.v



    dirsize=validate_size_directory(directory)

    if (debug):
        print "ARGV: %s" % argv
        print "method: %s" % method
        print "volume: %s" % volume
        print "directory: %s" % directory
        print "Size of directory %d" % dirsize


    instanceType="t1.micro"

    if 'EC2_BACKUP_FLAGS_AWS' in os.environ:
        flags=os.environ.get('EC2_BACKUP_FLAGS_AWS')
        instanceType=flags.split(' ')[1]



    newInstance = run_instance(instanceType)

    region=newInstance.placement

    cleanInst=newInstance


    if volume == None:
        volumeSize = calculate_volume_size(dirsize)
        volId = create_volume(volumeSize,region)
    else:
        volId = volume
        time.sleep(10)


    conn.attach_volume(volId,newInstance.id,"/dev/xvdf")

    check_volume_attachment(newInstance.public_dns_name)

    cleanVol=volId

    print volId

    signal.signal(signal.SIGINT, signal_handler)
    prep_backup_host(newInstance.public_dns_name)

    if (method == "rsync"):
        print "Directory:%s" %directory
        print "Dest: %s" % newInstance.public_dns_name
        rsync_backup(dir=directory,dest=newInstance.public_dns_name)
    if (method == "dd"):
        print "Directory: %s" %directory
        print "Dest: %s" % newInstance.public_dns_name
        dd_backup(dir=directory,dest=newInstance.public_dns_name)




    exit_and_cleanup()



if __name__ == "__main__":
    main(sys.argv[1:])



