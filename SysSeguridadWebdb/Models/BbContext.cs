﻿using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;

namespace SysSeguridadWebdb.Models;

public partial class BbContext : DbContext
{
    public BbContext()
    {
    }

    public BbContext(DbContextOptions<BbContext> options)
        : base(options)
    {
    }

    public virtual DbSet<Rol> Rol { get; set; }

    public virtual DbSet<Usuario> Usuario { get; set; }
    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    { }


    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Rol>(entity =>
        {
            entity.HasKey(e => e.Id).HasName("PK__Rol__3214EC0773A63FCB");
        });

        modelBuilder.Entity<Usuario>(entity =>
        {
            entity.HasKey(e => e.Id).HasName("PK__Usuario__3214EC078152B9BB");

            entity.Property(e => e.Password).IsFixedLength();

            entity.HasOne(d => d.IdRolNavigation).WithMany(p => p.Usuario)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("FK1_Rol_Usuario");
        });

        OnModelCreatingPartial(modelBuilder);
    }

    partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
}
