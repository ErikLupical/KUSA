"use client";

import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Flashlight, Settings } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { PasswordChangingDialog } from "./password-changing-dialog";

export function AccountSettingsDialog() {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [openPasswordChangeDialog, setOpenPasswordChangeDialog] = useState(false);

  const handleLogOut = async () => {
    try {
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/auth/logout`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json", 
        },
      });

      if (response.ok) {
        window.location.href = "/";
      }
      else {
        const errorData = await response.json();
        console.error('Logout failed: ', errorData.error);
      }
    } catch (error) {
      console.error(error);
    }
  };

  const handleMyProfileClick = () => {
    setOpen(false); // Close the dialog
    router.push('/profile');
  };

  const handleOpenAdmin = () => {
    router.push('/admin');
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <button className="p-2 rounded hover:bg-gray-200 cursor-pointer">
          <Settings className="h-5 w-5 text-gray-600" />
        </button>
      </DialogTrigger>
      <DialogContent className="max-w-sm bg-white text-black">
        <DialogHeader>
          <DialogTitle>Account Settings</DialogTitle>
          <DialogDescription>Manage your account information and settings.</DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-3 mt-4">
          <button
            className="w-full text-left px-3 py-2 rounded hover:bg-gray-100 cursor-pointer"
            onClick={handleMyProfileClick}
          >
            My Profile
          </button>
          <button
            className="w-full text-left px-3 py-2 rounded hover:bg-gray-100 cursor-pointer"
            onClick={handleOpenAdmin}
          >
            Admin
          </button>
          {/* <button className="w-full text-left px-3 py-2 rounded hover:bg-gray-100 cursor-pointer" onClick={handleChangePasswordClick}>Change password</button> */}
          <PasswordChangingDialog
            openDialog={openPasswordChangeDialog}
            setOpenDialog={setOpenPasswordChangeDialog}
          />
          <button className="w-full text-left px-3 py-2 rounded hover:bg-gray-100 text-red-600 cursor-pointer" onClick={handleLogOut}>Sign out</button>
          <button className="w-full text-left px-3 py-2 rounded hover:bg-gray-100 text-red-600 cursor-pointer">Delete account</button>
        </div>
      </DialogContent>
    </Dialog>
  );
}