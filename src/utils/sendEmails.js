import nodemailer from 'nodemailer'
export const sendEmail=async ({to, subject, html})=>{
    //sender
   const transporter = nodemailer.createTransport({
    host: 'localhost',
    port: 465,
    secure:true,
    service:'gmail',
    auth:{
        user:process.env.EMAIL,
        pass:process.env.EMAILPASSWORD
    }
    
   })   
       //reciever 
       const emailInfo = await transporter.sendMail({
        from:`"paula girgis"<${process.env.EMAIL}>`,
        to,
        subject,
        html
        
       })
         
       if (emailInfo.accepted.length < 1){
        return false
       }
       else {
        return true
       }
       
//or     return emailInfo.accepted.length < 1 ? false : true

}